# Below we show the rules and evidences extracted from [62, 63, 64].
# [62] R. Browne, “North Korea hackers trying to steal bitcoin to evade sanctions.”
# https://www.cnbc.com/2017/09/12/north-korea-hackers-trying-to-steal-bitcoin-evade-sanctions.html
# [Online. Last accessed: 2017-11-25], 2017.
# [63] Skynews, “‘Strong evidence’ North Korea-linked group was behind NHS cyberattack.” https://news.sky.com/story/
# cyberattack-tech-firms-investigate-north-korea-linked-hackers-10879388
# [Online. Last accessed: 2017-11-26], 2017.
# [64] BBC-News, “More evidence for WannaCry ‘link’ to North Korean hackers.”
# http://www.bbc.co.uk/news/technology-40010996 [Online. Last accessed: 2017-11-30], 2017.

#evidence
malwareUsedInAttack(wannacry, wannacryattack).
malwareUsedInAttack(trojanAlphanc, wannacryattack).
malwareModifiedFrom(trojanAlphanc, backdoorDuuzer).
malwareUsedInAttack(trojanBravonc, wannacryattack).

# % 'backdoorBravonc' and 'infostealerFakepude' use similar code obfuscation techniques
similarCodeObfuscation(backdoorBravonc, infostealerFakepude).

# % 'wannacry' and 'backdoorCantopee' have some shared code
sharedCode(wannacry, backdoorCantopee).

# % wannacry attack occured on 2017 May
attackPeriod(wannacryattack, [2017, 5]).

# % wannacry attack did not have a specific target, multiple countries and industries were attacked
neg(specificTarget(wannacryattack)).

# % NHS was one of the targets
target(nhs, wannacryattack).
targetCountry(uk, wannacryattack).


#tech_rules
rule(r_t_similar1(M1, M2), similar(M1, M2),[similarCodeObfuscation(M1, M2)]).
rule(r_t_similar2(M1, M2), similar(M1, M2), [sharedCode(M1, M2)]).


# str_rules.pl
rule(r_str__linkedMalware(X, A1), isCulprit(X, A1),[malwareUsedInAttack(M1, A1), similar(M1, M2), malwareLinkedTo(M2, X), notFromBlackMarket(M1), notFromBlackMarket(M2)]).
