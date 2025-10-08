FROM ghcr.io/calamity-inc/soup:e466303cb678817b6437e7fa29a3679176b61323

COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++17 -lstdc++ -fno-rtti

ENTRYPOINT ["./a.out"]
