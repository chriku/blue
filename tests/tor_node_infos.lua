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
infos["dannenberg"] = -- http://193.23.244.244/tor/server/authority
[==[router dannenberg 193.23.244.244 443 0 80
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABrfRAQeLVERZl+vVbtY3LeBI2H/7p3Rtc3JuY3FFr29llXCzAQAgBAD3/EVt
H1aDEkCNWSqMJ39L/nkPWKpsB5x8pN5qLq/8SNQSxhqzVw6m3NjzAF8eI6jXEhqq
LzH3AmFpcs+Pwzq/yEq1dvTWnkZFMpjB0QkRaUWuecs1+wG8fSiLzRsacAI=
-----END ED25519 CERT-----
master-key-ed25519 9/xFbR9WgxJAjVkqjCd/S/55D1iqbAecfKTeai6v/Eg
or-address [2001:678:558:1000::244]:443
platform Tor 0.4.2.5 on OpenBSD
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2 Padding=2 FlowCtrl=1
published 2020-01-28 10:24:54
fingerprint 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123
uptime 1879499
bandwidth 40960 1073741824 3137781
extra-info-digest E19C1A44050876984AB4A046332E7DC8614852A2 6RXxrQNmjPcMMeu9a31YilFw31y/P18ZBom5fjEUYQg
caches-extra-info
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMR2/Psvd3W1hm1prSRnMkl74PKHqtWxMMFAPrdOVsxKLFltAHH8KCQt
qh/siSRNLYA1L+vQuwl4tGVZsoUFjFU7xkNiSg39stQGu45BgKam1K8iehuIm0mC
ZC+0pGJcKmFLlJmqWXyEwvm9vtkSJ365wzJ0eY0+C/g9sUIvnMCZAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAKs8FLryN+QTw6XBRqkOF1Z3ztMW1DC9heyCz6v7QX+NGYVgjK/sioNy
MlqgZ0j45ClvL16TzFUR39vk/4JBMmYCxfr2T95BojufnM67Qo+2aoc92secL3ol
LAn0CWjPmMS0tgLz51vN7/FlARAl7A83PfINXTkvxuYPkriTSJE7AgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
iG2S0JFkCxfVPtcRAcD4RM1Y34iwqkW3cvvxxv9yuj2bNOCyoUmFvJMq+ozypjqg
Dwm4RwyXuE2fC7cbgTBmT/dT8ZoIVwU0NJmxXXfd08fbvXAsDb/G0SJqNwaMQbOw
bsQpvtvdX8OE6DIFbs4Cp5F5pyDMsP0TsGsAvFqLij4=
-----END CROSSCERT-----
ntor-onion-key-crosscert 0
-----BEGIN ED25519 CERT-----
AQoABrVDAff8RW0fVoMSQI1ZKownf0v+eQ9YqmwHnHyk3mour/xIAB9Pqx8puiw8
g1H1OaOWSqCarFPpjs1U9swP3bgpmrq6jvkBJ8U0bvUDrWQLBt+lF5L2iYJq2Ixf
ypWdNKttkA0=
-----END ED25519 CERT-----
hidden-service-dir
contact Andreas Lehner
ntor-onion-key LePmtWTArw6/nKoHiAmuRDPV6GDSq71aBSh3NMR+GGY=
reject *:*
tunnelled-dir-server
router-sig-ed25519 FhskRCUJcq2RTut3KsNP9my86GmsVM5Q7BwJS9cvSEvcqK+b9O3bd1Y/Vrxq8uBrVkuyT7bENfnrsWciLt/qDg
router-signature
-----BEGIN SIGNATURE-----
lKsIRwWamXgTOwEroa9gVGT++k/imGT2TkMhN1Uj0fSC65kN8KMX1zWxSUxtr4qh
x6X5QdvrdGznncza/YE3dKzc8XdFXD7+t1tSYDSeoWPMpSkB1ydOqZ4a1x9cpXR9
9tBum03jkts+VIF/SOZ3XzNeQwtFkVa3o2sXxfJDiXA=
-----END SIGNATURE-----

]==]
infos["ExitNinja"] = -- http://46.165.245.154/tor/server/authority
[==[router ExitNinja 46.165.245.154 443 0 80
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABrO3AQkQdNg1TbwgU2Xul7DS+PRyUbuc6tA3gh7Jlwp/y+PjAQAgBAC/3naT
e9I9b1KkIZhCX/ZzjAwEuSWH4dPbWJn44fkpASxMCzM/oglj6Ar8Vuc9gzpnQgN1
0Npoxf/EDf6KwYvPTdHO23Ay0K0c5+FlsNF0KiaOl/HnHM9+RJpsfbsynAM=
-----END ED25519 CERT-----
master-key-ed25519 v952k3vSPW9SpCGYQl/2c4wMBLklh+HT21iZ+OH5KQE
platform Tor 0.4.2.5 on Linux
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2 Padding=2 FlowCtrl=1
published 2020-01-29 00:57:38
fingerprint 749E F4A4 34DF D00D AB31 E93D E862 33FB 916D 31E3
uptime 1850427
bandwidth 1073741824 1073741824 73523245
extra-info-digest 9C0570CB95A1BE05B7C647A24753EB1D3D2C368C INNqN1lvAnoTCVWU8etXMa0pCxkZndAmV1kw9wElFNo
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANmx/oMuLN3Vf3UltcjfOkBqgxZf4Jd7JlnnSAZnJJj6wQHV2spjzgr/
z9O7GPqF0HjBuJVP4Tk2TwfdKpNiwwfYgx/qp7PbwVB2uIoflWdA+LGmrdIzIamz
4tYibUTiWJBI411mJUx5FyUZVD+mH/hSW5RbbO39/sf+C6na98QxAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAO4gRuBr4h8aDG0TnHxoVgYOO1oVdREqOkF31uXSw7CDNTvOKGQkooXI
tnTVM5gpqBIVxmVnGvLTbGx/qnrxWqH5eysFSYAdY3HWcCLKJasVGG0zsYBPhs3K
ieYVFEHqyX2uEKL4LaTZITGX1E3JcdjW5m6D9OCyhnKKQg9IbpbtAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
QE7ySWZo1Gf8QoxhqoI1J2H3oPI34gOfVlIHGMc7PYceCxHn5fBO+8bzPEv+aToW
ZtKd2a+2EAn+FsCM5XDGy3zRDRVlnnl5q6oakyc4nEkmVcfdYO34zYE8m8X4Jlk2
GnwDB/wt2zXyP141FZhF29vPTvfq84kBGEMJtv9Ba3I=
-----END CROSSCERT-----
ntor-onion-key-crosscert 1
-----BEGIN ED25519 CERT-----
AQoABrVRAb/edpN70j1vUqQhmEJf9nOMDAS5JYfh09tYmfjh+SkBAIKzzoaCwu4D
yYDHV229kugQ1qPLRGhpntlRuDj73/00FB3WPvLr6U6bOoGa9PI5m0RHDlAifMfM
e9V5z3trQgU=
-----END ED25519 CERT-----
family $615ABEA2DE76EB3760BC51E7306BAA59F15CD8F2 $749EF4A434DFD00DAB31E93DE86233FB916D31E3 $973607526BE9C8FDA03EBBAF527D67AE6FFD65DD $AFF2FC5C6F793B6E147EB93C1897D6DDA49E54FD
hidden-service-dir
contact TNinja <abuse-team _at_ tor _dot_ ninja>
ntor-onion-key irNaVbYmMuVjqfud6zTwFhH/+xm3f2rJ+bUFjOQXz1Q=
reject 0.0.0.0/8:*
reject 169.254.0.0/16:*
reject 127.0.0.0/8:*
reject 192.168.0.0/16:*
reject 10.0.0.0/8:*
reject 172.16.0.0/12:*
reject 46.165.245.154:*
reject *:22
reject *:25
reject *:109
reject *:110
reject *:143
reject *:465
reject *:587
reject *:119
reject *:563
reject *:2710
reject *:6881-6889
reject *:6969
reject *:6970
reject *:55000
accept *:*
tunnelled-dir-server
router-sig-ed25519 PcOTwuO1hQgJpEsfIGawdWvSBufzQO+ek/MbBwjjXxxdhdbo+Cug2W/OwuObl+x92jYI3fLYkTRrcrrdsmIeDw
router-signature
-----BEGIN SIGNATURE-----
3WjS8QcimD1OfhmapnoZxqUmp21cZIGAP5YWCs3apqH8a4GXmSk6Apk7CnfL/mzp
c9zswZc8hxbFmkd0eDBU1x7y6eprfwdbTKAAIZ28l4XKczjJ+CUeRvip7MDkNcxs
XRN1BfnPiM6E5KmCfEIon9saEdP6J/AwfQGcANsLMns=
-----END SIGNATURE-----

]==]
infos[""] = [==[]==]
infos[""] = [==[]==]
infos[""] = [==[]==]
return infos
