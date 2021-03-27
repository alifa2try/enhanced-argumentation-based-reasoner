rule(r_t_neghighSkill(Att), neg(highLevelSkill(Att)), []).
rule(r_t_highSkill1(Att), highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(r_t_highSkill2(Att), highLevelSkill(Att), [malwareUsedInAttack(M, Att),usesZeroDayVulnerabilities(M)]).
rule(r_t_highSkill3(Att), neg(highLevelSkill(Att)), [malwareUsedInAttack(M,Att), neg(notFromBlackMarket(M))]).
rule(r_t_highSkill4(Att), highLevelSkill(Att), [malwareUsedInAttack(M, Att),sophisticatedMalware(M)]).
rule(r_t_highResource0(Att), neg(requireHighResource(Att)),[neg(highLevelSkill(Att))]).
rule(r_t_highResource1(Att), requireHighResource(Att), [highLevelSkill(Att)]).
rule(r_t_highResource2(Att), requireHighResource(Att), [target(T, Att), highSecurity(T)]).
rule(r_t_highResource3(Att), requireHighResource(Att), [highVolumeAttack(Att), longDurationAttack(Att)]).
rule(r_t_IPdomain1(S, M), ccServer(S, M), [malwareUsedInAttack(M, Att), attackSourceIP(IP, Att), ipResolution(S, IP, _D)]).
rule(r_t_IPdomain2(S, M), neg(ccServer(S, M)), [malwareUsedInAttack(M, Att),attackSourceIP(IP, Att), spoofedIP(IP, Att), ipResolution(S, IP, _D)]).
rule(r_t_IPdomain3(S, M), neg(ccServer(S, M)), [malwareUsedInAttack(M, Att),attackSourceIP(IP, Att), attackPeriod(Att, D1), ipResolution(S, IP, D), neg(recent(D, D1))]).


% to get auto ip resolution via virustotal
rule(r_t_IP(IP, Date), ip(IP, Date), [ip(IP), attackPeriod(Att, Date)]).
rule(r_t_noLocEvidence(X, Att), neg(attackPossibleOrigin(X, Att)), []).
rule(r_t_srcIP1(X, Att), attackPossibleOrigin(X, Att), [attackSourceIP(IP, Att), ipGeoloc(X, IP)]).
rule(r_t_srcIP2(X, Att), attackPossibleOrigin(X, Att), [majorityIpOrigin(X, Att)]).
rule(r_t_spoofIP(X, Att), neg(attackPossibleOrigin(X, Att)), [attackSourceIP(IP, Att), spoofedIP(IP, Att), ipGeoloc(X, IP)]).
rule(r_t_spoofIPtor(IP), spoofedIP(IP, Att), [attackSourceIP(IP, Att), targetServerIP(TargetServerIP, Att), torIP(IP, TargetServerIP)]).
rule(r_t_lang1(X, Att), attackPossibleOrigin(X, Att), [sysLanguage(L, Att),firstLanguage(L, X)]).
rule(r_t_lang2(X, Att), attackPossibleOrigin(X, Att), [languageInCode(L, Att),firstLanguage(L, X)]).
rule(r_t_infra(X, Att), attackPossibleOrigin(X, Att), [infraUsed(Infra, Att), infraRegisteredIn(X, Infra)]).
rule(r_t_domain(X, Att), attackPossibleOrigin(X, Att), [malwareUsedInAttack(M, Att), ccServer(S, M), domainRegisteredDetails(S, _, Addr), addrInCountry(Addr, X)]).

rule(r_t_recent1(Y), recent([Y, _], [Y, _]), []).
rule(r_t_recent2(Y1, Y2, M1, M2), recent([Y1, M1], [Y2, M2]), M1 > M2]).
rule(r_t_recent3(Y1, Y2, M1, M2), recent([Y1, M1], [Y2, M2]), M2 > M1]).
rule(r_t_attackOriginDefault(X, Att), neg(attackOrigin(X, Att)), []).
rule(r_t_attackOrigin(X, Att), attackOrigin(X, Att), [attackPossibleOrigin(X, Att)]).
rule(r_t_conflictingOrigin(X, Y, Att), neg(attackOrigin(X, Att)), [attackPossibleOrigin(X, Att), attackPossibleOrigin(Y, Att), country(X), country(Y), X \= Y]).

rule(r_t_bm(M), notFromBlackMarket(M), [infectionMethod(usb, M), commandAndControlEasilyFingerprinted(M)]).


rule(r_t_similarDefault(M1, M2), neg(similar(M1, M2)), []).
rule(r_t_similar(M1, M2), similar(M1, M2), [similarCCServer(M1, M2), M1 \= M2]).
rule(r_t_simCC1(M1, M2), similarCCServer(M1, M2), [ccServer(S, M1), ccServer(S, M2)]).
rule(r_t_simCC2(M1, M2), similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2), S1 \= S2, domainRegisteredDetails(S1, _, A),domainRegisteredDetails(S2, _, A)]).
rule(r_t_simCC3(M1, M2), similarCCServer(M1, M2), [ccServer(S1, M1), ccServer(S2, M2), S1 \= S2, domainRegisteredDetails(S1, Name, _), domainRegisteredDetails(S2, Name, _)]).


rule(r_t_similar1(M1, M2), similar(M1, M2), [similarCodeObfuscation(M1, M2)]).
rule(r_t_similar2(M1, M2), similar(M1, M2), [sharedCode(M1, M2)]).
rule(r_t_similar3(M1, M2), similar(M1, M2), [malwareModifiedFrom(M1, M2)]).
rule(r_t_similar4(M1, M2), similar(M1, M2), [M1 \= M2, fileCharaMalware(C1, M1), fileCharaMalware(C2, M2), similarFileChara(C1, C2)]).


rule(r_t_targetted(Att), specificTarget(Att), [malwareUsedInAttack(M, Att), specificConfigInMalware(M)]).


rule(r_t_similarFileChara1(C1, C2), similarFileChara(C1, C2), [fileChara(Filename, _, _, _, _, _, C1), fileChara(Filename, _, _, _, _, _,C2)]).
rule(r_t_similarFileChara2(C1, C2), similarFileChara(C1, C2), [fileChara(_, MD5,_, _, _, _, C1), fileChara(_, MD5, _, _, _, _, C2)]).
rule(r_t_similarFileChara3(C1, C2), similarFileChara(C1, C2), [fileChara(_, _,_, _, Desc, _, C1), fileChara(_, _, _, _, Desc, _, C2)]).


rule(r_t_similarFileChara4(C1, C2), similarFileChara(C1, C2), [fileChara(_, _, Size, CompileTime, _, Filetype, C1), fileChara(_, _, Size, CompileTime, _, Filetype, C2)]).


% preferences
rule(p1_t(), prefer(r_t_attackOrigin(X, Att), r_t_attackOriginDefault(X, Att)),[]).
rule(p4a_t(), prefer(r_t_srcIP1(X, Att), r_t_noLocEvidence(X, Att)), []).
rule(p4b_t(), prefer(r_t_srcIP2(X, Att), r_t_noLocEvidence(X, Att)), []).
rule(p5_t(), prefer(r_t_lang1(X, Att), r_t_noLocEvidence(X, Att)), []).
rule(p6_t(), prefer(r_t_lang2(X, Att), r_t_noLocEvidence(X, Att)), []).
rule(p7_t(), prefer(r_t_infra(X, Att), r_t_noLocEvidence(X, Att)), []).
rule(p8_t(), prefer(r_t_domain(X, Att), r_t_noLocEvidence(X, Att)), []).
rule(p9a_t(), prefer(r_t_spoofIP(X, Att), r_t_srcIP1(X, Att)), []).
rule(p9b_t(), prefer(r_t_spoofIP(X, Att), r_t_srcIP2(X, Att)), []).
rule(p10a_t(), prefer(r_t_highSkill1(Att), r_t_neghighSkill(Att)), []).
rule(p10b_t(), prefer(r_t_highSkill2(Att), r_t_neghighSkill(Att)), []).
rule(p10c_t(), prefer(r_t_highSkill4(Att), r_t_neghighSkill(Att)), []).
rule(p11b_t(), prefer(r_t_highSkill3(Att), r_t_highSkill2(Att)), []).
rule(p11c_t(), prefer(r_t_highSkill3(Att), r_t_highSkill4(Att)), []).
rule(p12a_t(), prefer(r_t_highResource1(Att), r_t_highResource0(Att)), []).
rule(p12b_t(), prefer(r_t_highResource2(Att), r_t_highResource0(Att)), []).
rule(p12c_t(), prefer(r_t_highResource3(Att), r_t_highResource0(Att)), []).
rule(p13a_t(), prefer(r_t_IPdomain2(S, M), r_t_IPdomain1(S, M)), []).
rule(p13b_t(), prefer(r_t_IPdomain3(S, M), r_t_IPdomain1(S, M)), []).
rule(p14a_t(), prefer(r_t_similar(M1, M2), r_t_similarDefault(M1, M2)), []).
rule(p14b_t(), prefer(r_t_simCC1(M1, M2), r_t_similarDefault(M1, M2)), []).
rule(p14c_t(), prefer(r_t_simCC2(M1, M2), r_t_similarDefault(M1, M2)), []).
rule(p14d_t(), prefer(r_t_simCC3(M1, M2), r_t_similarDefault(M1, M2)), []).
