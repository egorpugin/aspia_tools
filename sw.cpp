void build(Solution &s) {
    auto &aspia = s.addProject("aspia_tools");

    auto cppstd = cpplatest;

    auto &router_relay = aspia.addLibrary("router_relay");
    {
        auto &t = router_relay;
        t += cppstd;
        t += "src/router_relay/.*"_rr;
        t.Public += "org.sw.demo.aspia.proto"_dep;
        t.Public += "org.sw.demo.boost.asio"_dep;
        t.Public += "pub.egorpugin.primitives.templates2"_dep;
        t.Public += "org.sw.demo.openssl.crypto"_dep;
    }

    auto &testapp = aspia.addExecutable("testapp");
    {
        auto &t = testapp;
        t.PackageDefinitions = true;
        t += cppstd;
        t += "src/test/.*"_rr;
        t += router_relay;
        t += "pub.egorpugin.primitives.sw.main"_dep;
    }
}
