local infos = {}
infos["moria1"] = -- http://128.31.0.34:9131/tor/server/authority
[==[
router moria1 128.31.0.34 9101 0 9131
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABsDLAcNTxZiZh+xxKU3qBhH2VLOuY2iD/N/BkostwpoDKYH3AQAgBADKnR/C
2nhpr9UzJkkbPy83sqbfNh63VgFnCpkSTULAclhv2P6nRVPvh34XZ1S5+a99vTFJ
LkfrnonMMypKtZ3ct1qQGf2W1PsfXzQIkFUGs1xcLD+NwSIMBMRRNAzEMwg=
-----END ED25519 CERT-----
master-key-ed25519 yp0fwtp4aa/VMyZJGz8vN7Km3zYet1YBZwqZEk1CwHI
platform Tor 0.4.3.0-alpha-dev on Linux
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2 Padding=2 FlowCtrl=1
published 2020-01-28 05:04:47
fingerprint 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31
uptime 64871
bandwidth 512000 104857600 3074048
extra-info-digest 838C67764EDD14D4962EFFD1189CCC9544CCF7C4 NobmwjuWxaIJKrKdl4CBeacj3lD8SOG8GBWAv24laFc
caches-extra-info
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALUl/2ZuvWmautGOih1XRx9/4+4zqwWc531CTKouINAuEZZM4kPgVjX7
JRbluomDqa27DLQbvryNdTJIjjNU+AsmxFY/U6Dav1jF9PwcHsJcbCuSapBng4xq
/nBb24X/+SH0BMCemQfdVbmW8f11rfzUoxwt9UVeLRfBhvH2CZ1jAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALtJ9uD7cD7iHjqNA3AgsX9prES5QN+yFQyr2uOkxzhvunnaf6SNhzWW
bkfylnMrRm/qCz/czcjZO6N6EKHcXmypehvP566B7gAQ9vDsb+l7VZVWgXvzNc2s
tl3P7qpC08rgyJh1GqmtQTCesIDqkEyWxwToympCt09ZQRq+fIttAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
RI3kuh/OpgIGWuvOXUukDyzjrT922yYyvebSsyouVP5OhqBPpTvByk/ZxJK9dbeX
OZdDGuURTdKcpGR1xyK6chgt8qiCc6zXRpEfcSEzJLSLNKrQEVdQkYCpZ2v7dZHY
qkJBTukei8WxbYJopFiwDDgQi3iJyiTANXq6smx5HtA=
-----END CROSSCERT-----
ntor-onion-key-crosscert 0
-----BEGIN ED25519 CERT-----
AQoABrU+AcqdH8LaeGmv1TMmSRs/Lzeypt82HrdWAWcKmRJNQsByALgiuBiA4cjP
rxMmwbvyOgAeX1XyoJ+WTvkfD6dbSLjOSC7eRwN+y1zI0XtytfMy4jvd4XUFMZ4D
DKymJAa7fA0=
-----END ED25519 CERT-----
hidden-service-dir
contact 1024D/EB5A896A28988BF5 arma mit edu
ntor-onion-key A9OYkoVFLF4G/Jwd+5gJ6hyaaw+/8aR47K6X8Sojo2E=
reject *:*
tunnelled-dir-server
router-sig-ed25519 H2JwGRJggIuNaKu0m/jpcPqkuthaFRdoEsjpSRFFzjDeG589sg17+jHzZ2aR41hAme0cZQra/xMRB2U/ADBQBg
router-signature
-----BEGIN SIGNATURE-----
GX5BLBfReaYPdkLR/ObmDqVLDnFxolTKWCDizD8LuG4gn6GPTHmUuzh7LAIQk6MJ
wsgqKmgwlfaftwwRWiy6RFnXP1xLg116595qWxY8h/Z5NZPYZH5hAujjKX1bw7Ry
T89tRvM9Kid58bqVUIeRlBZ3qyz9Ylu4wKlooCH6Ltc=
-----END SIGNATURE-----
]==]
infos["gabelmoo"] = -- http://131.188.40.189/tor/server/authority
[==[
router gabelmoo 131.188.40.189 443 0 80
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABrpXAT5rQcL+PPw9SZ29/sTVK51BaGO5O4hPAjQxeHs/6h2pAQAgBABdxrTI
U/gqnJ2hRohfphxdtIA/Cy6iR2fJsmgLncL/IysF+7Jy734LE+tNL5g05bwJZWtb
4OCaIbzcLw9u6PYkC9iXOSHvE+k0dfcnXE3SYeVUYLu3l7YTsyZ8Ac63egw=
-----END ED25519 CERT-----
master-key-ed25519 Xca0yFP4KpydoUaIX6YcXbSAPwsuokdnybJoC53C/yM
or-address [2001:638:a000:4140::ffff:189]:443
platform Tor 0.4.2.5 on Linux
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2 Padding=2 FlowCtrl=1
published 2020-01-28 15:10:44
fingerprint F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281
uptime 64863
bandwidth 40960 125829120 3362969
extra-info-digest A61F3214BBFA03E5D36873D44BA530A9ED2B415E C49aC4JktDNXI4/psdQrNYLmk1GbIR53ABIHEfdLZC4
caches-extra-info
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMa9m6NWGCD4YGEAzFqJa3PM1idu5lbRR/lOb6n88KY5ujGY9qS8ZQrv
Xi/p/jr1YRcUyAd3af9UZsl2zKvEveLKLPvGytTAXvL2bFtZC/c6NQkq7Ysm+NmB
Mee0PNftiHKazKduK0KpEHfgLIo/7T+s8KMhR5QUw/227ipHK9OtAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMjPhp0QAN8WQeP8sDg+mnM7hnPExcXTOfsmt7Sl2k3fHcHeAJnYu10V
/hb6RBhubi1HRg6fYF5PwZWOppxRj90WX3n2JEcQh88+4tuQNQ2jOxXQ/hBkyf0w
klrx6Fh8ana1VX+QXInfRW5z3eaANXqvdCvDG5jfUrz6pj8WGPrxAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
BQbSl7G4qLTUl7r1J+ycPYXHjRsRMDNcw8/snnQYYUTUKMApz8kdkWZpp/twKpA4
WOlpuz5Ly6wmdNloDs7wyd4eXZHm1yonMumNGdaC1BNGsGg3YArR0AM5qdL26nUn
zFHBkinlSyKyIzbWuLQTq4vsMH8uV7Hauu3EK0VP0A4=
-----END CROSSCERT-----
ntor-onion-key-crosscert 0
-----BEGIN ED25519 CERT-----
AQoABrVIAV3GtMhT+CqcnaFGiF+mHF20gD8LLqJHZ8myaAudwv8jAHzbzUbH7CBh
//gijILOmXCIuPmvUPMxvKZ01u78x1fD3CYP8mTmxqJG3PB1EzRCcYG+xVufA9nB
8ssAw17p5g8=
-----END ED25519 CERT-----
hidden-service-dir
contact 4096R/261C5FBE77285F88FB0C343266C8C2D7C5AA446D Sebastian Hahn <tor@sebastianhahn.net> - 12NbRAjAG5U3LLWETSF7fSTcdaz32Mu5CN
ntor-onion-key 3Xa96Oxoqcjug92Kshv8DqClstN6GEAbko3EMQNSMVU=
reject *:*
tunnelled-dir-server
router-sig-ed25519 IwfGIH7fpxeksZU4AeQOK054KVtw046XYJhtvkp5Jt9SMp5dZWlPKRi9MspoesvOmCtLi1v7gs+qHnyOodfmCQ
router-signature
-----BEGIN SIGNATURE-----
lnuoI/14he0j+pP26b/ImdxRPUIKNJ1tWp6FocHUK3uWd8WHR72lq9fs36ri+TC/
wGShTwYk9aqf0gBV9qWVnuD6H9CVnZdcMTYcdWkpzzkY1sicT0B7f9RF1qFoPMdo
JJ4ZyX0enzBs7IgsgmbjmuLEf8VdzWLVAsE1tGm03mU=
-----END SIGNATURE-----
]==]
infos[""] = [==[]==]
infos[""] = [==[]==]
infos[""] = [==[]==]
infos[""] = [==[]==]
infos[""] = [==[]==]
return infos
