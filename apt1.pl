# Below we show the rules and evidences extracted from [56, 57]
# [56] Nicole Perlroth, “Online Banking Attacks Were Work of Iran, U.S. Officials Say.” http://www.nytimes.com/2013/01/09/technology/
# online-banking-attacks-were-work-of-iran-us-officials-say.html
# [Online. Last accessed: 2017-11-21], 2013.
# [57] D. Goldman, “Major banks hit with biggest cyberattacks in history.” http://money.cnn.com/2012/09/27/technology/bank-cyberattacks/index.html
# [Online. Last accessed: 2017-11-22], 2012.


# Evidences
# many IPs detected, but the majority of them originated from china
majorityIpOrigin(china, apt1). 

# attacker's system default language configuration detected from malware is chinese
sysLanguage(chinese, apt1).

firstLanguage(chinese, china).
infraUsed(apt1_infra, apt1).

# infrastructure registered in china
infraRegisteredIn(china, apt1_infra).

# china has economic motive to attack organizations in the infocomm industry victims 'v'
hasEconomicMotive(china, infocomm).

# this group of victims are part of the infocomm industry
industry(infocomm, v).

highVolumeAttack(apt1).
longDurationAttack(apt1).

# 'superhard' and 'dota' are handle names of individuals identified as part of the attackers
identifiedIndividualInAttack(superhard, apt1).
identifiedIndividualInAttack(dota , apt1). 

#'superhard' was geolocated to frequent one of the government facilities in china
geolocatedInGovFacility(superhard, china).

# 'dota' released some comments on social media hinting that he was related to the chinese government
publicCommentsRelatedToGov(dota , china).


#rules
rule(srcIP(X,Att), attackPossibleOrigin(X,Att),[majorityIpOrigin(X,Att)]).
rule(lang1(X,Att), attackPossibleOrigin(X,Att), [sysLanguage(L,Att), firstLanguage(L, X)]).
rule(infra(X,Att), attackPossibleOrigin(X,Att), [infraUsed(Infra,Att), infraRegisteredIn(X, Infra)]).
rule(highResource3(Att), requireHighResource(Att),[highVolumeAttack(Att),longDurationAttack(Att)]).


# op_rules.pl
rule(ecMotive(C,T), hasMotive(C, Att), [industry(T), target(T, Att), hasEconomicMotive(C, T), specificTarget(Att)]).
rule(r_op_hasResources2(X), hasResources(X), [cybersuperpower(X)]).


# str_rules.pl
rule(r_str__motiveAndLocation(C, Att), isCulprit(C, Att), [attackOrigin(C, Att), hasMotive(C, Att), country(C)]).
rule(r_str__motiveAndCapability(C, Att), isCulprit(C, Att),[hasMotive(C, Att), hasCapability(C, Att)]).





