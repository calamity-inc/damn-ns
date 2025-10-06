#include <iostream>

#include <base64.hpp>
#include <dns_records.hpp>
#include <dnsHeader.hpp>
#include <dnsQuestion.hpp>
#include <dnsResource.hpp>
#include <HttpRequestTask.hpp>
#include <json.hpp>
#include <MemoryRefReader.hpp>
#include <Server.hpp>
#include <SharedPtr.hpp>
#include <Socket.hpp>
#include <SocketAddr.hpp>
#include <string.hpp>

#ifdef DOCKER
#include <signal.h>
#endif

using namespace soup;

static Server serv;
static std::string upstream_server;
static std::unordered_map<std::string, std::vector<SharedPtr<dnsRecord>>> hosts{};

struct ForwardDnsTask : public Task
{
	SharedPtr<Worker> sock;
	SocketAddr addr;
	HttpRequestTask http;

	static Uri makeUri(const std::string& data)
	{
		std::string url = "https://";
		url.append(upstream_server);
		url.append("/dns-query?dns=");
		url.append(base64::urlEncode(data));
		return Uri(url);
	}

	ForwardDnsTask(SharedPtr<Worker>&& sock, const SocketAddr& addr, const std::string& data)
		: sock(std::move(sock)), addr(addr), http(makeUri(data))
	{
	}

	void onTick() final
	{
		if (http.tickUntilDone())
		{
			if (http.result)
			{
				static_cast<Socket*>(sock.get())->udpServerSend(addr, std::move(http.result->body));
			}
			setWorkDone();
		}
	}
};

int main()
{
	{
		auto config = json::decode(string::fromFile("damn-ns-config.json"));
		if (!config || !config->isObj())
		{
			std::cout << "Invalid damn-ns-config.json" << std::endl;
			return 1;
		}

		upstream_server = config->asObj().at("upstream_doh").asStr().value;

		for (const auto& e : config->asObj().at("hosts").asObj())
		{
			IpAddr addr;
			addr.fromString(e.second->asStr().value);
			hosts.emplace(
				e.first->asStr().value,
				std::vector<SharedPtr<dnsRecord>>{ soup::make_shared<dnsARecord>(e.first->asStr().value, 69420, addr.getV4()) }
			);
		}
	}

	const auto bindres = serv.bindUdp(53, [](Socket& sock, SocketAddr&& addr, std::string&& data)
	{
		MemoryRefReader sr(data);

		dnsHeader dh;
		dh.read(sr);

		if (dh.isResponse())
		{
			std::cout << "Ignoring non-query from " << addr.toString() << std::endl;
			return;
		}

		if (dh.qdcount != 1)
		{
			std::cout << "Ignoring query with more than 1 question from " << addr.toString() << std::endl;
			return;
		}

		dnsQuestion dq;
		dq.read(sr);

		if (dq.qclass != DNS_IN)
		{
			std::cout << "Ignoring non-internet query from " << addr.toString() << std::endl;
			return;
		}

		// DNS is case-insensitive, so make query all lowercase for simplicity.
		for (auto& entry : dq.name.name)
		{
			string::lower(entry);
		}

		auto qname = string::join(dq.name.name, '.');

		std::cout << "Query for " << qname << " from " << addr.toString() << std::endl;

		if (auto e = hosts.find(qname); e != hosts.end())
		{
			const auto& rrs = e->second;

			dh.setIsResponse(true);
			dh.bitfield1 |= (1 << 2); // AA
			dh.bitfield2 = 0; // RA = 0, Z = 0, RCODE = OK

			// Count num. answers
			dh.ancount = 0;
			for (const auto& rr : rrs)
			{
				if (rr->type == dq.qtype
					|| dq.qtype == DNS_ALL
					)
				{
					++dh.ancount;
				}
			}

			// Reset num. additionals in case query had some
			dh.arcount = 0;

			StringWriter sw;
			dh.write(sw);
			dq.write(sw);

			for (const auto& rr : rrs)
			{
				if (rr->type != dq.qtype
					&& dq.qtype != DNS_ALL
					)
				{
					continue;
				}
				dnsResource dr{};
				if (rr->name == qname)
				{
					dr.name.ptr = 12; // point to name in dnsQuestion
				}
				else
				{
					dr.name.name = string::explode(rr->name, '.'); // could be more efficient for subdomains
				}
				dr.rtype = rr->type;
				dr.rclass = DNS_IN;
				dr.ttl = rr->ttl;
				dr.rdata = rr->toRdata();
				dr.write(sw);
			}
			sock.udpServerSend(addr, sw.data);
		}
		else
		{
			serv.add<ForwardDnsTask>(serv.getShared(sock), addr, data);
		}
	});
	if (!bindres)
	{
		std::cout << "Failed to bind UDP/53" << std::endl;
		return 1;
	}
	std::cout << "Listening on UDP/53" << std::endl;
#ifdef DOCKER
	signal(SIGTERM, [](int) { exit(0); });
#endif
	serv.run();
}
