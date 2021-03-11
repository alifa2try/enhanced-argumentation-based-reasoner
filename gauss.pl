
# Below we show the rules and evidences extracted from [59, 60, 58]
# [59] Kaspersky Lab Global Research and Analyst Team, “Gauss: Abnormal Distribution,” tech. rep., Kaspersky Lab, 2012.
# [58] A. Fitzpatrick, “Meet the ‘Gauss’ Virus, Stuxnet and Flame’s New Cousin.” https://mashable.com/2012/08/09/gauss-virus/?europe=true#M8v5wovsp5q0
# [Online. Last accessed: 2018-05-31], 2012.
# [60] L. Dignan, “Meet Gauss: The latest cyber-espionage tool.” https://www.zdnet.com/article/meet-gauss-the-latest-cyber-espionage-tool/
# [Online. Last accessed: 2018-05-31], 2012.


# evidences
# % expected: equationGroup (linkedMalware)
malwareUsedInAttack(gauss, gaussattack).
sophisticatedMalware(gauss).

# Note: other countries were attacked too, but focus is on lebanon
targetCountry(lebanon, gaussattack).

# % gauss malware infects machines by USB
infectionMethod(usb, gauss).

# % the control and command used by gauss was easily fingerprinted.
# Unique fingerprint detection of C&C traffic can be used by
# anti-virus software to flag the malware
commandAndControlEasilyFingerprinted(gauss).

# % 'gowin7' and 'secuurity' are command and control servers used by gauss
ccServer(gowin7, gauss).
ccServer(secuurity, gauss).

# % the domains are registered under the name 'Adolph Dybevek' and under the address 'Prinsen Gate 6'
domainRegisteredDetails(gowin7, adolph_dybevek, prinsen_gate_6).
domainRegisteredDetails(secuurity , adolph_dybevek, prinsen_gate_6).

# % the attack occured in 2011 Sept
attackPeriod(gaussattack, [2011, 9]).


# % background evidence (flame malware)
# % 'flame' malware said to by made by 'equation group'
malwareLinkedTo(flame, equationGrp).

target(middleeast , flameattack).
malwareUsedInAttack(flame, flameattack).
ccServer(gowin7, flame).
ccServer(secuurity, flame).
domainRegisteredDetails(gowin7, adolph_dybevek, prinsen_gate_6).
domainRegisteredDetails(secuurity, adolph_dybevek, prinsen_gate_6).


#tech_rules
rule(bm, notFromBlackMarket(M),[infectionMethod(usb,M),commandAndControlEasilyFingerprinted(M)]).

# % 2 malwares are similar to each other if they have similar C&C
rule(similar,similar(M1, M2), [similarCCServer(M1, M2), M1 \= M2]).
rule(simCC1, similarCCServer(M1, M2), [ccServer(S, M1), ccServer(S,M2)]).
rule(simCC2, similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2), S1 \= S2, domainRegisteredDetails(S1,_,A),domainRegisteredDetails(S2,_,A)]).
rule(simCC3, similarCCServer(M1, M2), [ccServer(S1, M1),ccServer(S2, M2), S1 \= S2, domainRegisteredDetails(S1,Name,_),domainRegisteredDetails(S2,Name,_)]).


# % str_rules
rule(linkedMalware(X,A1), isCulprit(X,A1),[malwareUsedInAttack(M1,A1), similar(M1,M2),malwareLinkedTo(M2,X), notFromBlackMarket(M1),notFromBlackMarket(M2)]).






