
:- compile('/home/faysal/Documents/Attribution/ABR/gorgias-src-0.6d/lib/gorgias.pl').
:- compile('/home/faysal/Documents/Attribution/ABR/gorgias-src-0.6d/ext/lpwnf.pl').

% Rules
rule(notGuiltyByDefault(X), (neg(isCulprit(X)), []).
rule(ipGeolocation(X), isCulprit(X), [ipGeoloc(X, IP)]).
rule(spoofedIp(X), neg(isCulprit(X)), [ipGeoloc(X, IP), spoofedIP(IP)]).

% Facts
rule(fact1, ipGeoloc(china, ip1), []).
rule(fact2, ipGeoloc(us, ip2), []).
rule(fact3, spoofedIP(ip1), []).

%Priority/Preference
rule(p1(X), prefer(spoofedIp(X), ipGeolocation(X)), []).
rule(p2(X), prefer(ipGeolocation(X), notGuiltyByDefault(X)), []).