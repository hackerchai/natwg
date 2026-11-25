# Changelog

## [0.4.0](https://github.com/hackerchai/natwg/compare/v0.3.0...v0.4.0) (2026-11-25)


### Features

* add natwg detect to tell whether the network can host natwg ([bfa57a8](https://github.com/hackerchai/natwg/commit/bfa57a8c52cd689134730f79c15da5ece15c1193))
* export WireGuard, Surge and mihomo configurations ([bf97181](https://github.com/hackerchai/natwg/commit/bf97181135cb56275835e1597f76fabbae26e3ea))
* export WireGuard, Surge and mihomo configurations ([3ca7d54](https://github.com/hackerchai/natwg/commit/3ca7d544e8bd7189759c24b52b49390cf90fbe58))
* follow uplink events and recover TXT endpoints on handshake failure ([b7a87ac](https://github.com/hackerchai/natwg/commit/b7a87ac2d1eaadc4f577164f6887d0cb850df49d))
* follow uplink events and recover TXT endpoints on handshake failure ([2cd4f8f](https://github.com/hackerchai/natwg/commit/2cd4f8f14e645ad8efdd30fc1337c88082221fe9))
* initialize WireGuard servers from network detection ([d14deeb](https://github.com/hackerchai/natwg/commit/d14deeb98128122546df8e818dd52137c70f190f))
* initialize WireGuard servers from network detection ([87c54dc](https://github.com/hackerchai/natwg/commit/87c54dcaa1da7ec96d9a1d0135f4098eef6c34c5))
* natwg detect tells whether the network can host natwg ([cd39d14](https://github.com/hackerchai/natwg/commit/cd39d145a406b10abb1c2b546717b97abe5d72cf))
* publish the public IP as an A record in public mode ([347e42d](https://github.com/hackerchai/natwg/commit/347e42d6dcf25dd79a60258531c6451098101a82))
* publish the public IP as an A record in public mode ([0811400](https://github.com/hackerchai/natwg/commit/08114008284ca9371d1915de7db32734be94cfa8))


### Bug Fixes

* **client:** recover TXT peers across retries and roaming ([3f9cb5c](https://github.com/hackerchai/natwg/commit/3f9cb5c4d318436b6ee8d004c653da57d35f44c0))
* **client:** start handshake grace at first TXT discovery ([24fbb2d](https://github.com/hackerchai/natwg/commit/24fbb2d0bfa9a41aaddbac396fdd7e2024486327))
* ignore unrouted traffic when pausing client keepalives ([e82bccf](https://github.com/hackerchai/natwg/commit/e82bccfd0f6a29a7643b6e328a098b4981af1c3a))
* make natwg detect claim only what it saw, and keep UPnP safe ([f989382](https://github.com/hackerchai/natwg/commit/f98938255aa49138b60356afbb02608761a3a779))
* preserve peer keys and recover native endpoint snapshots ([ee29c31](https://github.com/hackerchai/natwg/commit/ee29c31408e8bbf417ee7d7066f838cee7b341cd))
* prove the review fixes of public mode in the network lab ([2c9de26](https://github.com/hackerchai/natwg/commit/2c9de26240162f4dd2bf2d2dccf3d2cb7d9bb0ac))
* prove the review's cases in the network lab ([a6f3e8d](https://github.com/hackerchai/natwg/commit/a6f3e8d0e8f6358f70af44ff8dfde315f49884d4))
* verify first-peer endpoints and reload the initialized server ([b3df7da](https://github.com/hackerchai/natwg/commit/b3df7da01a193c14c65e61724aa5353596028362))
* write only an exact A record of an IP confirmed now ([b35065d](https://github.com/hackerchai/natwg/commit/b35065d3f7ccab3e73ffeccbf9760a1648880704))

## [0.3.0](https://github.com/hackerchai/natwg/compare/v0.2.0...v0.3.0) (2026-11-25)


### Features

* add natwg config set for the subnet, the LANs and the routes ([45359ad](https://github.com/hackerchai/natwg/commit/45359ad45767ec61b457555cff2c2e47abf48c0e))
* choose the tunnel subnet and any number of LANs, with natwg config set ([4bdef97](https://github.com/hackerchai/natwg/commit/4bdef977ee14b7f105d4ecb45e72e049497aa426))
* let a server serve any number of LANs ([cb40813](https://github.com/hackerchai/natwg/commit/cb40813b87a89f5b249de5718cc4eb0acec4757f))
* self-update from the R2 download site with GitHub Releases fallback ([a82937b](https://github.com/hackerchai/natwg/commit/a82937b3f452ceb31acf61cb8107a74c141e4d65))
* self-update from the R2 download site with GitHub Releases fallback ([8ba41cd](https://github.com/hackerchai/natwg/commit/8ba41cdf7da567e8afe3c06daaa164636def46db))


### Bug Fixes

* keep addresses in place when the new subnet overlaps the old one ([916f316](https://github.com/hackerchai/natwg/commit/916f3166e85a759dfa6bcaf3f4c62d2ad0a33bc3))
* **update:** review findings on self-update ([290c4c2](https://github.com/hackerchai/natwg/commit/290c4c21e415985b94aa3d3cf6255e284a937106))

## [0.2.0](https://github.com/hackerchai/natwg/compare/v0.1.0...v0.2.0) (2026-11-24)


### ⚠ BREAKING CHANGES

* **config:** `natwg config import-legacy` is gone. Write the config by hand or keep using the one the cutover produced.

### Features

* **client:** run natwg as a WireGuard client that follows the TXT record ([1f871db](https://github.com/hackerchai/natwg/commit/1f871dbbcb3757cba105a09d088a6352ee4563ba))
* **config:** import a wg-quick client config with its keys ([507bd43](https://github.com/hackerchai/natwg/commit/507bd43b8eede2d2d107822ccc014ffe8c429cec))
* **peer:** add, list and remove the clients of a server ([7820fda](https://github.com/hackerchai/natwg/commit/7820fdac48b9879e7329b4af75cced932bd1e8b0))
* **service:** install natwg client as its own service ([bd006d8](https://github.com/hackerchai/natwg/commit/bd006d8bf9f4f01e5137de5307d05120633ef4c7))


### Bug Fixes

* **client:** judge a stale handshake by the session lifetime and keepalive ([31442cd](https://github.com/hackerchai/natwg/commit/31442cd7e40f2bfbb539391f212917bf10b2a114))
* **client:** leave the LAN the host sits on out of the tunnel routes ([3404012](https://github.com/hackerchai/natwg/commit/340401278b51002be1ff8023aa540750b68e1b93))


### Code Refactoring

* **config:** remove config import-legacy ([bc072f8](https://github.com/hackerchai/natwg/commit/bc072f85d03b5b477bcb635d98b1d41ac748dd70))

## 0.1.0 (2026-11-24)


### Features

* **cli:** add a hidden natwg daemon command for service managers ([7bfa5b8](https://github.com/hackerchai/natwg/commit/7bfa5b88ac00e8aa59ec7867749ed0d5c5391555))
* **cli:** add natwg probe stun, dns and txt ([53429a7](https://github.com/hackerchai/natwg/commit/53429a794ec52242584c132645fc33db736cdcd0))
* **cli:** add natwg server --foreground and natwg doctor loopback ([cdee56e](https://github.com/hackerchai/natwg/commit/cdee56e5778265f7a267b8aa574aa9e17891d37f))
* **config:** add natwg config doctor for an imported config ([b124261](https://github.com/hackerchai/natwg/commit/b12426150b41f18b4615376a9846a435e1106f99))
* **config:** add the natwg crate, config model and legacy import ([b7a7402](https://github.com/hackerchai/natwg/commit/b7a7402a4aa75867b8d2c07ce6f80d6374f921bb))
* **config:** add the natwg crate, config model and legacy import ([717cf12](https://github.com/hackerchai/natwg/commit/717cf129d1808ff60c7e86a2c85fa1b993ff08f6))
* **config:** name the server instance that owns the NAT rules ([f9a88fb](https://github.com/hackerchai/natwg/commit/f9a88fb80e9b8c4ed4f3426e2965ef8f7b48c7aa))
* **doctor:** dial the mapping in the status file by default ([b4bcf0f](https://github.com/hackerchai/natwg/commit/b4bcf0fd8159b41c12007337cf201763e498099f))
* **doctor:** ping the tunnel address and the LAN through a client in process ([7338808](https://github.com/hackerchai/natwg/commit/733880881a9c539ea376c13a96ba3e3065337237))
* land the wire layer and the embedded tunnel on main, with the P3 safety fixes ([2fdb60c](https://github.com/hackerchai/natwg/commit/2fdb60cafd33d3b87b117df2360793d2174b944c))
* **nat:** plan LAN NAT as a pf anchor and an nftables table ([7c86bd8](https://github.com/hackerchai/natwg/commit/7c86bd81f5e9adeff4b4f1e41bc89113b28d32c5))
* **netcfg:** plan the tunnel address, MTU and routes as commands ([cf7308a](https://github.com/hackerchai/natwg/commit/cf7308a7afb4ea15ad7faf67afc76475392dc3c0))
* **server:** keep the carrier mapping alive with a STUN keepalive ([06b4e01](https://github.com/hackerchai/natwg/commit/06b4e0163dfbd7187d78dcf79e8869bec37ff25b))
* **server:** keep the mapping alive, publish it, and supervise the tunnel ([b1b2798](https://github.com/hackerchai/natwg/commit/b1b27987caa2ec1d01d8f14f3326286d54ff5dce))
* **server:** publish the mapping as the Cloudflare TXT record ([e1d9c34](https://github.com/hackerchai/natwg/commit/e1d9c346471917c67502d19306d4e2b3e0aac574))
* **server:** renew the UPnP lease on the home router ([cacc02a](https://github.com/hackerchai/natwg/commit/cacc02a899b78889c80c44dc5ddf963c0e651e03))
* **server:** supervise the tunnel and rebuild it when it dies ([a454295](https://github.com/hackerchai/natwg/commit/a45429505c03fa6974b54a3e74557f8509446d0f))
* **service:** install natwg as a system service ([8c8be82](https://github.com/hackerchai/natwg/commit/8c8be82a867abf3ad5dc54b4c07c0c7c93bace26))
* **service:** install natwg as a system service ([868e1af](https://github.com/hackerchai/natwg/commit/868e1af4906f9527f35ac3bf396c6aff12a5f27d))
* **service:** uninstall a service by its instance name ([1e09dbd](https://github.com/hackerchai/natwg/commit/1e09dbde0ee36f777b8045e96621091d3c7bfdde))
* **status:** add the status file and natwg status ([1215b85](https://github.com/hackerchai/natwg/commit/1215b850b84ea9a83110bdb2ab09fafcd204f6d0))
* **tunnel:** hand out the STUN port, peer stats and a NAT re-check ([9d0b6c8](https://github.com/hackerchai/natwg/commit/9d0b6c85513313d3b93cfe9fbf754db96b648bea))
* **tunnel:** run gotatun with the config's peers on a TUN or in memory ([19d2194](https://github.com/hackerchai/natwg/commit/19d219419141b4a70af34a25b32dfb3e03b21a1b))
* **wire:** add the STUN Binding codec ([8dffc91](https://github.com/hackerchai/natwg/commit/8dffc91ef84ab623102669665167a4f7df9cb30a))
* **wire:** resolve A and TXT records through the uplink interface ([b572eff](https://github.com/hackerchai/natwg/commit/b572eff8c325a26098c41364011ae625a8f98d68))
* **wire:** share one interface-bound socket between STUN and WireGuard ([ee59b97](https://github.com/hackerchai/natwg/commit/ee59b97aecb58b7db6ef9b262c394965fff2d15b))


### Bug Fixes

* **cli:** keep running when nobody reads the output ([bd7ed23](https://github.com/hackerchai/natwg/commit/bd7ed23208fee579ab4c075e011c9095b2bcfaf6))
* **cli:** stop the server on SIGHUP ([c360be5](https://github.com/hackerchai/natwg/commit/c360be5aeea5b001a4b21cafc874a47e5c02fae3))
* **config:** close the review findings on secrets and the legacy import ([32d55e9](https://github.com/hackerchai/natwg/commit/32d55e9a1c54b7a29409ca94885c6defc115d253))
* **config:** guard the real config before the cutover writes it ([a6c4116](https://github.com/hackerchai/natwg/commit/a6c41161aaf3fa6a6c7b062f9cfc2130f2859bc9))
* **config:** never echo a legacy key name longer than 19 characters ([33a2f45](https://github.com/hackerchai/natwg/commit/33a2f45f27af2b5fb4e7862c091ae4dbc8188cc3))
* **config:** refuse values that take routes or rules natwg does not own ([a023cf5](https://github.com/hackerchai/natwg/commit/a023cf57bdeb015524bb37eecc559c0d9a0574eb))
* **doctor:** refuse --attempts 0 when the command line is parsed ([29d408f](https://github.com/hackerchai/natwg/commit/29d408f016de6ceb478b4391f9fa5069070a0eaf))
* **nat:** check that Linux turned IP forwarding on ([d4f7801](https://github.com/hackerchai/natwg/commit/d4f78012e42fc81c07facdd1a155cb62f10409c1))
* **nat:** refuse an anchor or a table that holds rules of someone else ([76ec4ce](https://github.com/hackerchai/natwg/commit/76ec4ce488c2f8da3bfc2af207a3ba5b7d2f9196))
* **nat:** remove the rules when the server panics ([0bce2a1](https://github.com/hackerchai/natwg/commit/0bce2a1e2e192db60569f0246766bd346855e8e0))
* **netcfg:** refuse a tunnel subnet that another Linux device routes ([5c4383c](https://github.com/hackerchai/natwg/commit/5c4383ca49139bd3179e5eacfe46c8f64cc93494))
* **server:** count a TXT that holds the mapping as published ([717d60b](https://github.com/hackerchai/natwg/commit/717d60bf4b39c52e6a60c979a492c46f79fd0eed))
* **server:** delay a missed status or NAT tick instead of bursting it ([199dbe4](https://github.com/hackerchai/natwg/commit/199dbe4b8d638e9bbd86b233081fac32c0647534))
* **server:** write the status as soon as the mapping or the TXT changes ([a5d3f2b](https://github.com/hackerchai/natwg/commit/a5d3f2b597cc7f9adc653cb3c6e3eaaec4c2023f))
* **service:** install only under directories that only root can write ([65400a2](https://github.com/hackerchai/natwg/commit/65400a22d48a847ab6e21732c6283bcf507ea22c))
* **service:** report a started service only once its tunnel is up ([e1ac600](https://github.com/hackerchai/natwg/commit/e1ac600f2a0866637e6665d01304fca3320fd311))
* **service:** validate the install before it changes the host ([d876d61](https://github.com/hackerchai/natwg/commit/d876d611ddb4643626c60ea5ccaa14dce8f4b590))
* **status:** exit 1 when the status shows the server is not serving ([bca0ebf](https://github.com/hackerchai/natwg/commit/bca0ebf65be866f8bd6abb323ebb59991afe27d8))
* **status:** give each instance its own default status file ([0f2dac4](https://github.com/hackerchai/natwg/commit/0f2dac402a57083cb941b0d8b8112a4e4059c6cb))
* **tunnel:** keep the utun control socket out of child processes ([7c82733](https://github.com/hackerchai/natwg/commit/7c82733e559ab98146df26d2ca80a3098198ed2a))
* **tunnel:** name the peers that share a key in PEER_DUPLICATE ([7c84777](https://github.com/hackerchai/natwg/commit/7c8477749cdb0ad76e8b4f17399d19f156fcb050))
* **tunnel:** refuse a peer route that another utun holds on macOS ([de361af](https://github.com/hackerchai/natwg/commit/de361af561fd7e19ed22b38ea314e714e542dc8d))
* **tunnel:** refuse a tunnel address that another interface holds ([06abadc](https://github.com/hackerchai/natwg/commit/06abadcb9734d569b0f4a07b4dfff02471c8934e))
* **tunnel:** stop reporting a handshake as old as the device ([967e035](https://github.com/hackerchai/natwg/commit/967e035ca925c28c070f082832b106baf51fd517))
* **wire:** close the P2 review findings on probes, DNS and rebinding ([f958b1f](https://github.com/hackerchai/natwg/commit/f958b1fbfff0360cfe3bcc682506072ead2dae3d))
* **wire:** deliver only the answer to the pending STUN request ([853125a](https://github.com/hackerchai/natwg/commit/853125affa297894e3bd5e06458261d16b3b186f))
* **wire:** name the query in every DNS error and pin the buffer and default list ([7accc17](https://github.com/hackerchai/natwg/commit/7accc17e23b34131335f4b0961c506e80c0ac153))
