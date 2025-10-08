FROM ghcr.io/calamity-inc/soup:fc84e5230b4e58c663758fdb4b461b2e9448eda2

COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++17 -lstdc++ -fno-rtti

ENTRYPOINT ["./a.out"]
