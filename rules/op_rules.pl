%% Main rules:
abducible(specificTarget(_Att), []).
abducible(contextOfAttack(political, _Att), []).
abducible(contextOfAttack(economic, _Att), []).


rule(r_op_hasResources1(X), hasResources(X), [gci_tier(X, leading)]).
rule(r_op_hasResources2(X), hasResources(X), [cybersuperpower(X)]).
rule(r_op_hasNoResources(X), hasNoResources(X), [gci_tier(X, initiating)]).


% more than one country targetted
rule(r_op_notTargetted(Att), neg(specificTarget(Att)), [targetCountry(T1, Att), targetCountry(T2, Att), T1 \= T2]).


rule(r_op_hasCapability1(X, Att), hasCapability(X, Att), [neg(requireHighResource(Att))]).
rule(r_op_hasCapability2(X, Att), hasCapability(X, Att), [requireHighResource(Att), hasResources(X)]).
rule(r_op_noCapability1(X, Att), neg(hasCapability(X, Att)), [requireHighResource(Att), neg(hasResources(X))]).
rule(r_op_noCapability2(X, Att), neg(hasCapability(X, Att)), [hasNoResources(X)]).


rule(r_op_ecMotive(C, T), hasMotive(C, Att), [target(T, Att), industry(T), contextOfAttack(economic, Att), hasEconomicMotive(C, T), specificTarget(Att)]).
rule(r_op_pMotive(C, T), hasMotive(C, Att), [targetCountry(T, Att), attackPeriod(Att, Date1), contextOfAttack(political, Att), hasPoliticalMotive(C, T, Date2), dateApplicable(Date1, Date2), specificTarget(Att)]).
rule(r_op_pMotive1(C, T, Date), hasPoliticalMotive(C, T, Date), [imposedSanctions(T, C, Date)]).
rule(r_op_conflict(X, T), hasMotive(X, Att), [targetCountry(T, Att), attackPeriod(Att, Date1), news(Event, T, Date2), dateApplicable(Date1, Date2), causeOfConflict(X, T, Event), specificTarget(Att)]).
rule(r_op_conflict1(X, T), hasMotive(X, Att), [target(T, Att), attackPeriod(Att, Date1), news(Event, T, Date2), dateApplicable(Date1, Date2), causeOfConflict(X, T, Event), specificTarget(Att)]).
rule(r_op_nonGeopolitics1(C, T), neg(hasMotive(C, Att)), [targetCountry(T, Att), country(T), country(C), goodRelation(C, T)]).
rule(r_op_nonGeopolitics2(C, T), neg(hasMotive(C, Att)), [targetCountry(T, Att), country(T), country(C), goodRelation(T, C)]).
rule(r_op_grpPastTargets(Group, Att), hasMotive(Group, Att), [target(T, Att), prominentGroup(Group), pastTargets(Group, Ts), member(T, Ts)]). %WEAK RULE


rule(r_op_claimResp0(X, Att), existingGroupClaimedResponsibility(X, Att), [claimedResponsibility(X, Att)]).
rule(r_op_claimResp1(X, Att), neg(existingGroupClaimedResponsibility(X, Att)), [claimedResponsibility(X, Att), noPriorHistory(X)]).


rule(r_op_social1(P, C), governmentLinked(P, C), [geolocatedInGovFacility(P,C)]).
rule(r_op_social2(P, C), governmentLinked(P, C), [publicCommentsRelatedToGov(P,C)]).


%% politicalIndustries are industries that are closely related to well-being of country/sensitive to national interests
rule(r_op_context(economic, Att), contextOfAttack(economic, Att), [target(T, Att), industry(Ind, T), normalIndustry(Ind)]).
rule(r_op_context(political, Att), contextOfAttack(political, Att), [target(T,Att), country(T)]).
rule(r_op_context1(political, Att), contextOfAttack(political, Att), [target(T,Att), industry(Ind, T), politicalIndustry(Ind)]).


%% Auxiliary rules
%% Y2 M2 is before Y1 M1 but recent enough (within 1 year)
rule(r_op_date(ongoing), dateApplicable(_, ongoing), []).
rule(r_op_date1(Y, M), dateApplicable([Y, M], [Y, M]), []).
rule(r_op_date2(Y, M1, M2), dateApplicable([Y, M1], [Y, M2]), [M2 < M1]).
rule(r_op_date3(Y1, Y2), dateApplicable([Y1, _], [Y2, _]), [Y2 < Y1, Y2 > (Y1 - 2)]).


% preferences
rule(p1a_op(),prefer(r_op_ecMotive(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p1b_op(),prefer(r_op_ecMotive(C,T),r_op_nonGeopolitics2(C,T)),[]).
rule(p2a_op(),prefer(r_op_conflict(C,T),r_op_nonGeopolitics1(C,T)),[]).
rule(p2b_op(),prefer(r_op_conflict(C,T),r_op_nonGeopolitics2(C,T)),[]).


rule(p3a_op(), prefer(r_op_conflict1(C, T), r_op_nonGeopolitics1(C, T)), []).
rule(p3b_op(), prefer(r_op_conflict1(C, T), r_op_nonGeopolitics2(C, T)), []).
rule(p4a_op(), prefer(r_op_pMotive(C, T), r_op_nonGeopolitics1(C, T)), []).
rule(p4b_op(), prefer(r_op_pMotive(C, T), r_op_nonGeopolitics2(C, T)), []).
rule(p5_op(), prefer(r_op_claimResp1(X, A), r_op_claimResp0(X, A)), []).
rule(p6_op(), prefer(r_op_noCapability2(X, Att), r_op_hasCapability1(X, Att)),[]).
