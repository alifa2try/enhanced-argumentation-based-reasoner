# Below we show the rules and evidences extracted from [56, 57].
# [56] Nicole Perlroth, “Online Banking Attacks Were Work of Iran, U.S. Officials Say.” http://www.nytimes.com/2013/01/09/technology/
# online-banking-attacks-were-work-of-iran-us-officials-say.html
# [Online. Last accessed: 2017-11-21], 2013.
# [57] D. Goldman, “Major banks hit with biggest cyberattacks in history.” http://money.cnn.com/2012/09/27/technology/bank-cyberattacks/index.html
# [Online. Last accessed: 2017-11-22], 2012.


# Evidences
targetCountry(usa , usbankhack).

# usa imposed a new wave of sanctions
imposedSanctions(usa, iran, [2012, 2]).

# in the us bank hack, corporate cloud servers were hijacked
hijackCorporateClouds(usbankhack). sophisticatedMalware(itsoknoproblembro).

malwareUsedInAttack(itsoknoproblembro , usbankhack).

# the attack happened in 2012
attackPeriod(usbankhack , [2012, 9]). 

sophisticatedMalware(itsoknoproblembro).
malwareUsedInAttack(itsoknoproblembro , usbankhack).

# the attack happened in 2012 September
attackPeriod(usbankhack , [2012, 9]). 

# % target of the attack are US banks
target(us_banks, usbankhack). 

# the US banks belong to the banking
industry(banking, us_banks). 


# rules
# tech_rules.pl
rule(highSkill1, highLevelSkill(Att), [hijackCorporateClouds(Att)]).
rule(highSkill2, highLevelSkill(Att), [malwareUsedInAttack(M, Att),sophisticatedMalware(M)]).
rule(highResource1, requireHighResource(Att),[highLevelSkill(Att)]).


# % op_rules.pl
rule(hasCapability1, hasCapability(_X, Att),[neg(requireHighResource(Att))]).
rule(hasCapability2, hasCapability(X, Att),[requireHighResource(Att), hasResources(X)]).
rule(noCapability, neg(hasCapability(X, Att)),[requireHighResource(Att), neg(hasResources(X))]).

rule(pMotive(C,T), hasMotive(C, Att), [targetCountry(T, Att),attackPeriod(Att, Date1), hasPoliticalMotive(C, T, Date2),dateApplicable(Date1, Date2), specificTarget(Att)]).
rule(pMotive(C,T,Date), hasPoliticalMotive(C, T, Date),[imposedSanctions(T, C, Date)]).


#% str_rules.pl
rule(motiveAndCapability(C,Att),isCulprit(C,Att),[hasMotive(C,Att),hasCapability(C,Att)]).