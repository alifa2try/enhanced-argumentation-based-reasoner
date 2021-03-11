# Below we show the rules and evidences extracted from [14, 15, 16].

# [14] A. Altman and Z. J. Miller, “Sony Hack: FBI Accuses North Korea in Attack That Nixed The Interview.”
# http://time.com/3642161/sony-hack-north-korea-the-interview-fbi/
# [Online. Last accessed: 2018-01-10], 2014.
# [15] J. Roman, “FBI Defends Sony Hack Attribution.”
# https://www.bankinfosecurity.com/sony-a-7762 [Online. Last accessed: 2018-01-20], 2015.
# [16] B. Todd and B. Brumfield, “Experts doubt North Korea was behind the big
# Sony hack.” http://edition.cnn.com/2014/12/27/tech/north-korea-expert-doubts-about-hack/index.html 
# [Online. Last accessed: 2018-01-18], 2014.


# Evidences
claimedResponsibility(guardiansOfPeace, sonyhack).
target(sony, sonyhack).
targetCountry(united_states, sonyhack).
news(theInterview, sony,[2013,10]).
attackPeriod(sonyhack,[2014,11]).
causeOfConflict(north_korea, sony, theInterview).
majorityIpOrigin(north_korea, sonyhack).
malwareUsedInAttack(trojanVolgmer, sonyhack).
malwareUsedInAttack(backdoorDestover, sonyhack).


# Rules
# tech_rules.pl
rule(r_t_srcIP2(X, Att), attackPossibleOrigin(X, Att),[majorityIpOrigin(X, Att)]).


# op_rules.pl
rule(r_op_claimResp0(X, Att), existingGroupClaimedResponsibility(X,Att), [claimedResponsibility(X, Att)]).
rule(r_op_conflict1(X, T), hasMotive(X, Att), [target(T, Att),attackPeriod(Att, Date1), news(Event, T, Date2),dateApplicable(Date1, Date2), causeOfConflict(X, T, Event),specificTarget(Att)]).


# str_rules.pl
rule(r_str__claimedResp(X, Att), isCulprit(X, Att),[existingGroupClaimedResponsibility(X, Att)]).
rule(r_str__linkedMalware(X, A1), isCulprit(X, A1),[malwareUsedInAttack(M1, A1), similar(M1, M2)malwareLinkedTo(M2, X), notFromBlackMarket(M1)notFromBlackMarket(M2)]).
