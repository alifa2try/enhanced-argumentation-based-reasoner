# Below we show the rules and evidences extracted from [12, 11].
# [11] K. Zetter, Countdown to Zero Day : Stuxnet and the launch of the world’s
# first digital weapon. New York City, USA: Crown Publishing Group, 2014.
# [12] K. Zetter, “How Digital Detectives Deciphered Stuxnet, the Most Menacing
# Malware in History.” https://www.wired.com/2011/07/how-digital-detectives-deciphered-stuxnet/ 
# [Online. Last accessed: 2017-12-06], 2011.


# Evidences
# Evidences are listed in Prolog style for presentation purposes.
target(iranian_org,stuxnetattack).
industry(nuclear,iranian_org).
targetCountry(iran,stuxnetattack).
usesZeroDayVulnerabilities(stuxnet).
news(nuclear,iran,ongoing).
causeOfConflict(united_states, iran, nuclear).
causeOfConflict(israel, iran, nuclear).
attackPeriod(stuxnetattack,[2010,7]).
malwareUsedInAttack(stuxnet, stuxnetattack).
specificConfigInMalware(stuxnet).
infectionMethod(usb,stuxnet).
target(iran_nuclear_facilities, stuxnetattack).
industry(nuclear, iran_nuclear_facilities).


# Rules used
# tech_rules.pl
rule(r_t_targetted(Att), specificTarget(Att),[malwareUsedInAttack(M, Att), specificConfigInMalware(M)]).
rule(r_t_highSkill2(Att), highLevelSkill(Att), [malwareUsedInAttack(M, Att), usesZeroDayVulnerabilities(M)]).
rule(r_t_highResource1(Att), requireHighResource(Att), [highLevelSkill(Att)]).
rule(r_op_context1(political, Att), contextOfAttack(political,Att), [target(T, Att), industry(Ind, T), politicalIndustry(Ind)]).


# op_rules.pl
rule(r_op_conflict(X, T), hasMotive(X, Att), [targetCountry(T, Att), attackPeriod(Att, Date1), news(Event, T, Date2), dateApplicable(Date1, Date2), causeOfConflict(X, T, Event), specificTarget(Att)]).
rule(r_op_hasCapability2(X, Att), hasCapability(X, Att),[requireHighResource(Att), hasResources(X)]).
rule(r_op_hasResources2(X), hasResources(X), [cybersuperpower(X)]).


# str_rules.pl
rule(r_str__motiveAndCapability(C, Att), isCulprit(C, Att), [hasMotive(C, Att), hasCapability(C, Att)]).
