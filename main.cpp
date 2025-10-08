#include <iostream>

#include <base64.hpp>
#include <dns_records.hpp>
#include <dnsHeader.hpp>
#include <dnsQuestion.hpp>
#include <dnsResource.hpp>
#include <HttpRequestTask.hpp>
#include <json.hpp>
#include <MemoryRefReader.hpp>
#include <netAdaptor.hpp>
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
static const std::vector<SharedPtr<dnsRecord>> NORRS{};

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

static void handle_datagram(Socket& sock, SocketAddr&& addr, std::string&& data)
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

	const std::vector<SharedPtr<dnsRecord>>* rrs = &NORRS;
	if (auto e = hosts.find(qname); e != hosts.end())
	{
		rrs = &e->second;
	}
	else
	{
		if (!upstream_server.empty())
		{
			serv.add<ForwardDnsTask>(serv.getShared(sock), addr, data);
			return;
		}
	}

	dh.setIsResponse(true);
	dh.bitfield1 |= (1 << 2); // AA
	dh.bitfield2 = 0; // RA = 0, Z = 0, RCODE = OK

	// Count num. answers
	dh.ancount = 0;
	for (const auto& rr : *rrs)
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

	for (const auto& rr : *rrs)
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

int main()
{
	IpAddr bind_addr;

	{
		auto config = json::decode(string::fromFile("damn-ns-config.json"));
		if (!config || !config->isObj() || !config->asObj().contains("hosts"))
		{
			std::cout << "Invalid damn-ns-config.json" << std::endl;
#if SOUP_WINDOWS
			system("pause");
#endif
			return 1;
		}

		if (auto j_bind_addr = config->asObj().find("bind_addr"))
		{
			bind_addr.fromString(j_bind_addr->asStr().value);
		}

		if (auto upstream_doh = config->asObj().find("upstream_doh"))
		{
			upstream_server = upstream_doh->asStr().value;
		}

		for (const auto& e : config->asObj().at("hosts").asObj())
		{
			SharedPtr<dnsRecord> rr;
			IpAddr addr;
			addr.fromString(e.second->asStr().value);
			if (addr.isV4())
			{
				rr = soup::make_shared<dnsARecord>(e.first->asStr().value, 69420, addr.getV4());
			}
			else
			{
				rr = soup::make_shared<dnsAaaaRecord>(e.first->asStr().value, 69420, addr);
			}
			hosts.emplace(e.first->asStr().value, std::vector<SharedPtr<dnsRecord>>{ std::move(rr) });
		}
	}

_retry_bind:
	if (!(bind_addr.isZero() ? serv.bindUdp(53, handle_datagram) : serv.bindUdp(bind_addr, 53, handle_datagram)))
	{
		std::cout << "Failed to bind UDP/" << bind_addr.toStringForAddr() << ":53" << std::endl;
#if SOUP_WINDOWS
		if (bind_addr.isZero())
		{
			for (const auto& ad : netAdaptor::getAll())
			{
				if (ad.name.find("Virtual") == std::string::npos)
				{
					bind_addr = ad.ip_addr;
					goto _retry_bind;
				}
			}
		}
		system("pause");
#endif
		return 1;
	}
	std::cout << "Listening on UDP/" << bind_addr.toStringForAddr() << ":53" << std::endl;
#ifdef DOCKER
	signal(SIGTERM, [](int) { exit(0); });
#endif
	serv.run();
}
