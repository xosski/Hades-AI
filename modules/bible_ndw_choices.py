#!/usr/bin/env python3
"""
Bible Narrative Decision Weave Dataset
======================================

A structured dataset of the 80 biblical decision examples previously discussed,
formatted for use with the Narrative Decision Weave (NDW) prototype.

This is NOT an exhaustive list of every decision in the Bible. It is the
complete set of the 80 decision examples from the earlier NDW mapping.

Each record includes:
- reference
- actor
- situation
- options
- chosen action
- classification
- motives
- immediate consequences
- delayed consequences
- reusable decision principles
- a small decision tree

The module can:
1. print all decision trees,
2. search by actor/reference/principle,
3. export the corpus to JSON,
4. load the corpus into an NDW-like engine.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BibleDecision:
    id: str
    reference: str
    actor: str
    situation: str
    options: List[str]
    chosen: str
    classification: str
    motives: List[str]
    immediate_consequences: List[str]
    delayed_consequences: List[str]
    principles: List[str]
    tree: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def tree(question: str, branches: Dict[str, str]) -> Dict[str, Any]:
    return {
        "question": question,
        "branches": branches,
    }


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

BIBLE_DECISIONS: List[BibleDecision] = [

    BibleDecision(
        "gen_3_adam_eve",
        "Genesis 3",
        "Adam and Eve",
        "They are commanded not to eat from the tree of the knowledge of good and evil.",
        ["obey the command", "eat the forbidden fruit"],
        "eat the forbidden fruit",
        "bad",
        ["desire", "deception", "autonomy", "curiosity"],
        ["shame", "fear", "broken trust"],
        ["exile from Eden", "suffering and death enter the human story"],
        ["do_not_trade_trust_for_immediate_desire", "deception_can_distort_choice"],
        tree(
            "Obey the command or take the forbidden fruit?",
            {
                "obey": "remain within the given boundary",
                "eat": "gain forbidden knowledge but violate the command",
            },
        ),
    ),

    BibleDecision(
        "gen_4_cain",
        "Genesis 4",
        "Cain",
        "Cain becomes angry and jealous toward Abel.",
        ["master anger", "seek reconciliation", "attack Abel"],
        "attack Abel",
        "bad",
        ["jealousy", "anger", "resentment"],
        ["Abel is killed"],
        ["judgment", "alienation", "wandering"],
        ["unchecked_resentment_escalates", "anger_does_not_justify_violence"],
        tree(
            "How should Cain respond to jealousy?",
            {
                "master anger": "retain relationship and avoid violence",
                "reconcile": "address conflict",
                "attack": "murder leads to judgment",
            },
        ),
    ),

    BibleDecision(
        "gen_6_noah",
        "Genesis 6–8",
        "Noah",
        "Noah receives a warning about a coming flood and instructions to build an ark.",
        ["ignore the warning", "prepare as instructed"],
        "prepare as instructed",
        "good",
        ["faith", "obedience", "long-term preparation"],
        ["large immediate labor and social cost"],
        ["preservation through the flood"],
        ["prepare_for_low_probability_high_impact_risk", "accept_present_cost_for_future_survival"],
        tree(
            "Trust the warning enough to prepare?",
            {
                "ignore": "save present effort but remain exposed",
                "prepare": "pay large present cost for future preservation",
            },
        ),
    ),

    BibleDecision(
        "gen_12_abraham_leave",
        "Genesis 12",
        "Abraham",
        "Abraham is called to leave his land and go to an unknown destination.",
        ["stay with certainty", "leave in trust"],
        "leave in trust",
        "good",
        ["faith", "obedience", "willingness to leave certainty"],
        ["loss of familiar surroundings"],
        ["covenant journey and future blessing"],
        ["uncertainty_does_not_make_action_wrong", "commit_when_trustworthy_call_outweighs_comfort"],
        tree(
            "Remain with certainty or move toward an unknown calling?",
            {
                "stay": "retain present security",
                "leave": "accept uncertainty for a larger calling",
            },
        ),
    ),

    BibleDecision(
        "gen_12_abraham_sarah",
        "Genesis 12",
        "Abraham",
        "Abraham fears danger because of Sarah's beauty and misrepresents their relationship.",
        ["tell the truth", "misrepresent Sarah as sister"],
        "misrepresent Sarah as sister",
        "bad/complex",
        ["fear", "self-preservation"],
        ["temporary protection for Abraham", "danger and confusion for Sarah and others"],
        ["conflict and rebuke"],
        ["fear_can_generate_deceptive_shortcuts", "self_protection_can_shift_risk_onto_others"],
        tree(
            "Respond to danger with truth or deception?",
            {
                "truth": "accept risk without deception",
                "deceive": "reduce immediate fear while creating wider danger",
            },
        ),
    ),

    BibleDecision(
        "gen_13_abraham_lot",
        "Genesis 13",
        "Abraham",
        "Conflict develops between the households of Abraham and Lot.",
        ["demand first choice", "allow Lot to choose first"],
        "allow Lot to choose first",
        "good",
        ["peace", "generosity", "confidence"],
        ["gives up first choice of land"],
        ["avoids immediate conflict"],
        ["yielding_advantage_can_resolve_conflict", "peace_can_be_more_valuable_than_first_choice"],
        tree(
            "Compete for advantage or voluntarily yield first choice?",
            {
                "demand": "maximize personal control",
                "yield": "reduce conflict and preserve relationship",
            },
        ),
    ),

    BibleDecision(
        "gen_19_lots_wife",
        "Genesis 19",
        "Lot's wife",
        "She is warned not to look back while fleeing destruction.",
        ["continue forward", "look back"],
        "look back",
        "bad",
        ["attachment", "hesitation"],
        ["disobedience"],
        ["destruction"],
        ["do_not_reverse_course_when_escape_requires_commitment"],
        tree(
            "Continue the escape or look back?",
            {
                "forward": "continue toward safety",
                "look back": "break the warning and face consequence",
            },
        ),
    ),

    BibleDecision(
        "gen_22_abraham_isaac",
        "Genesis 22",
        "Abraham",
        "Abraham is commanded to offer Isaac.",
        ["refuse", "proceed in obedience"],
        "proceed in obedience",
        "good/extraordinarily difficult",
        ["faith", "obedience", "trust"],
        ["extreme emotional cost"],
        ["intervention and reaffirmed blessing"],
        ["deep_commitment_can_require_extreme_trust", "do_not_assume_immediate_appearance_is_final_outcome"],
        tree(
            "Trust the command despite enormous apparent cost?",
            {
                "refuse": "retain immediate security",
                "obey": "accept extreme uncertainty and trust",
            },
        ),
    ),

    BibleDecision(
        "gen_25_esau",
        "Genesis 25",
        "Esau",
        "Esau is hungry and offered food in exchange for his birthright.",
        ["preserve long-term inheritance", "trade birthright for immediate food"],
        "trade birthright for immediate food",
        "bad",
        ["hunger", "impulse", "short-term focus"],
        ["immediate satisfaction"],
        ["loss of high-value future inheritance"],
        ["do_not_trade_high_future_value_for_small_immediate_relief", "short_term_urgency_distorts_value"],
        tree(
            "Protect future value or satisfy immediate appetite?",
            {
                "preserve": "endure short-term discomfort",
                "trade": "gain immediate relief at enormous long-term cost",
            },
        ),
    ),

    BibleDecision(
        "gen_27_jacob_rebekah",
        "Genesis 27",
        "Jacob and Rebekah",
        "They seek Isaac's blessing through deception.",
        ["seek blessing honestly", "deceive Isaac"],
        "deceive Isaac",
        "bad/complex",
        ["ambition", "fear of losing blessing", "manipulation"],
        ["Jacob receives the blessing"],
        ["family fracture", "Esau's anger", "Jacob flees"],
        ["successful_deception_can_still_be_strategically_bad", "gain_without_trust_can_destroy_relationships"],
        tree(
            "Pursue desired outcome honestly or manipulate the process?",
            {
                "honest": "risk losing desired result",
                "deceive": "gain result while creating relational damage",
            },
        ),
    ),

    BibleDecision(
        "gen_37_joseph_brothers",
        "Genesis 37",
        "Joseph's brothers",
        "The brothers resent Joseph and consider how to respond.",
        ["restrain jealousy", "remove Joseph from the family", "kill Joseph"],
        "sell Joseph",
        "bad",
        ["jealousy", "resentment", "competition"],
        ["Joseph is enslaved", "family is deceived"],
        ["years of grief and later reckoning"],
        ["jealousy_can_turn_people_into_objects", "do_not_solve_status_conflict_by_harming_people"],
        tree(
            "How should jealousy toward Joseph be handled?",
            {
                "restrain": "preserve relationship",
                "sell": "remove rival through exploitation",
                "kill": "maximum irreversible harm",
            },
        ),
    ),

    BibleDecision(
        "gen_39_joseph",
        "Genesis 39",
        "Joseph",
        "Joseph is pressured by Potiphar's wife.",
        ["accept temptation", "refuse", "escape"],
        "refuse and escape",
        "good",
        ["integrity", "loyalty", "moral boundary"],
        ["false accusation", "imprisonment"],
        ["eventual elevation after later events"],
        ["integrity_over_immediate_reward", "short_term_loss_can_follow_good_choice"],
        tree(
            "Accept immediate reward or preserve integrity?",
            {
                "accept": "immediate pleasure with betrayal and risk",
                "refuse": "preserve integrity",
                "escape": "remove self from the situation",
            },
        ),
    ),

    BibleDecision(
        "gen_41_joseph_grain",
        "Genesis 41",
        "Joseph",
        "Egypt faces years of abundance followed by predicted famine.",
        ["consume abundance normally", "store grain systematically"],
        "store grain systematically",
        "good",
        ["foresight", "planning", "resource management"],
        ["reduced present consumption"],
        ["survival during famine", "regional stability"],
        ["store_surplus_before_predictable_shortage", "foresight_converts_abundance_into_resilience"],
        tree(
            "Spend abundance now or reserve for future scarcity?",
            {
                "consume": "maximize current use",
                "store": "accept current restraint for future survival",
            },
        ),
    ),

    BibleDecision(
        "gen_45_joseph_forgive",
        "Genesis 45",
        "Joseph",
        "Joseph has power over the brothers who betrayed him.",
        ["take revenge", "distance himself", "forgive and reconcile"],
        "forgive and reconcile",
        "good",
        ["mercy", "family restoration", "perspective"],
        ["gives up revenge"],
        ["family reconciliation and preservation"],
        ["power_does_not_require_revenge", "mercy_can_end_cycles_of_harm"],
        tree(
            "Use power for revenge or reconciliation?",
            {
                "revenge": "repay past harm",
                "distance": "avoid further relationship",
                "forgive": "restore relationship while acknowledging history",
            },
        ),
    ),

    BibleDecision(
        "exo_1_midwives",
        "Exodus 1",
        "Hebrew midwives",
        "Pharaoh orders the killing of Hebrew male infants.",
        ["obey Pharaoh", "protect the infants"],
        "protect the infants",
        "good",
        ["fear of God", "protection of innocent life", "moral courage"],
        ["risk punishment from authority"],
        ["lives are preserved"],
        ["authority_does_not_make_wrong_orders_right", "protect_innocent_life_over_unjust_command"],
        tree(
            "Obey unjust authority or protect innocent life?",
            {
                "obey": "reduce personal risk but harm innocents",
                "protect": "accept risk to prevent wrongdoing",
            },
        ),
    ),

    BibleDecision(
        "exo_2_moses",
        "Exodus 2",
        "Moses",
        "Moses sees an Egyptian beating a Hebrew.",
        ["seek lawful intervention", "restrain the aggressor", "kill the Egyptian"],
        "kill the Egyptian",
        "bad/complex",
        ["anger", "identification with the victim", "impulse"],
        ["Egyptian dies"],
        ["Moses flees Egypt"],
        ["righteous_anger_does_not_automatically_justify_lethal_action", "impulsive_force_can_create_new_crisis"],
        tree(
            "How should Moses respond to injustice?",
            {
                "intervene nonlethally": "stop harm without killing",
                "seek process": "pursue another response",
                "kill": "end immediate attack through irreversible violence",
            },
        ),
    ),

    BibleDecision(
        "exo_3_moses_calling",
        "Exodus 3–4",
        "Moses",
        "Moses is called to return to Egypt and confront Pharaoh.",
        ["continue avoiding the task", "accept the calling"],
        "accept the calling",
        "good",
        ["obedience", "courage despite self-doubt"],
        ["returns to danger and responsibility"],
        ["becomes leader in the Exodus"],
        ["fear_and_inadequacy_do_not_end_responsibility", "support_can_enable_difficult_calling"],
        tree(
            "Avoid the mission or accept responsibility?",
            {
                "avoid": "retain immediate safety",
                "accept": "face danger for a larger purpose",
            },
        ),
    ),

    BibleDecision(
        "exo_pharaoh",
        "Exodus 5–14",
        "Pharaoh",
        "Pharaoh repeatedly faces demands and escalating consequences.",
        ["release Israel", "continue refusing"],
        "continue refusing",
        "bad",
        ["pride", "control", "hardness", "political power"],
        ["temporary retention of control"],
        ["escalating plagues and catastrophic loss"],
        ["doubling_down_can_amplify_losses", "reassess_after_repeated_negative_feedback"],
        tree(
            "Change course after escalating evidence or continue refusing?",
            {
                "change": "accept loss of control and stop escalation",
                "refuse": "preserve pride temporarily while increasing cost",
            },
        ),
    ),

    BibleDecision(
        "exo_14_red_sea",
        "Exodus 14",
        "Moses and Israel",
        "Israel is trapped between Pharaoh's army and the sea.",
        ["panic and surrender", "move forward in trust"],
        "move forward in trust",
        "good",
        ["faith", "courage", "obedience"],
        ["enter apparent danger"],
        ["deliverance"],
        ["apparent_dead_end_may_still_contain_a_path", "panic_is_not_strategy"],
        tree(
            "Surrender to fear or move according to trusted instruction?",
            {
                "panic": "return toward former captivity",
                "move": "advance despite apparent impossibility",
            },
        ),
    ),

    BibleDecision(
        "exo_32_golden_calf",
        "Exodus 32",
        "Israelites",
        "Moses is absent longer than expected and the people become impatient.",
        ["wait", "create an idol"],
        "create an idol",
        "bad",
        ["impatience", "fear", "desire for visible control"],
        ["false celebration and misplaced worship"],
        ["judgment and broken covenant trust"],
        ["impatience_can_create_false_substitutes", "absence_of_immediate_feedback_does_not_justify_abandoning_commitment"],
        tree(
            "Wait under uncertainty or manufacture a substitute?",
            {
                "wait": "tolerate uncertainty",
                "idol": "replace uncertainty with a false object of confidence",
            },
        ),
    ),

    BibleDecision(
        "num_13_ten_spies",
        "Numbers 13–14",
        "Ten spies",
        "The spies see strong inhabitants in the promised land.",
        ["trust and proceed", "recommend retreat"],
        "recommend retreat",
        "bad",
        ["fear", "risk aversion", "focus on obstacles"],
        ["community panic"],
        ["lost opportunity and prolonged wandering"],
        ["fear_can_overweight_visible_threat", "majority_opinion_is_not_proof"],
        tree(
            "Proceed despite danger or retreat because of fear?",
            {
                "proceed": "accept risk toward objective",
                "retreat": "avoid immediate danger but lose opportunity",
            },
        ),
    ),

    BibleDecision(
        "num_13_joshua_caleb",
        "Numbers 13–14",
        "Joshua and Caleb",
        "Joshua and Caleb see the same danger as the other spies.",
        ["join majority fear", "advocate trust and advance"],
        "advocate trust and advance",
        "good",
        ["faith", "courage", "independent judgment"],
        ["social opposition"],
        ["eventual inheritance of the land"],
        ["same_evidence_can_support_different_judgments", "courage_can_require_minority_position"],
        tree(
            "Follow fearful consensus or maintain independent conviction?",
            {
                "consensus": "gain social alignment",
                "conviction": "accept isolation while pursuing believed objective",
            },
        ),
    ),

    BibleDecision(
        "num_20_moses_rock",
        "Numbers 20",
        "Moses",
        "Moses is instructed how to provide water but acts in anger.",
        ["follow instruction precisely", "strike the rock in anger"],
        "strike the rock in anger",
        "bad",
        ["anger", "frustration"],
        ["water is produced"],
        ["Moses faces serious consequence"],
        ["successful_output_does_not_validate_wrong_process", "anger_can_corrupt_execution"],
        tree(
            "Follow the prescribed method or act out of frustration?",
            {
                "follow": "achieve goal with fidelity",
                "strike": "achieve immediate result while violating instruction",
            },
        ),
    ),

    BibleDecision(
        "josh_2_rahab",
        "Joshua 2",
        "Rahab",
        "Rahab encounters Israelite spies and must decide whether to expose or protect them.",
        ["turn them in", "protect them"],
        "protect them",
        "good",
        ["faith", "courage", "allegiance"],
        ["personal danger"],
        ["Rahab and household are preserved"],
        ["courage_can_require_switching_allegiance", "protecting_others_can_involve_personal_risk"],
        tree(
            "Expose the spies or protect them?",
            {
                "expose": "align with current local authority",
                "protect": "accept risk based on new allegiance",
            },
        ),
    ),

    BibleDecision(
        "josh_7_achan",
        "Joshua 7",
        "Achan",
        "Achan encounters prohibited goods after Jericho.",
        ["leave them", "take and conceal them"],
        "take and conceal them",
        "bad",
        ["greed", "secrecy"],
        ["private gain"],
        ["community harm and judgment"],
        ["hidden_private_gain_can_create_public_cost", "concealment_compounds_wrongdoing"],
        tree(
            "Respect the restriction or take hidden gain?",
            {
                "leave": "forego private reward",
                "take": "gain secretly while creating systemic risk",
            },
        ),
    ),

    BibleDecision(
        "judg_6_gideon",
        "Judges 6–7",
        "Gideon",
        "Gideon receives unconventional instructions for confronting a much larger force.",
        ["rely on conventional numbers", "follow the unusual strategy"],
        "follow the unusual strategy",
        "good",
        ["faith", "obedience", "adaptive strategy"],
        ["accepts apparent numerical weakness"],
        ["victory"],
        ["smaller_force_can_win_with_different_strategy", "do_not_equate_resource_count_with_outcome"],
        tree(
            "Trust conventional strength or unconventional strategy?",
            {
                "conventional": "maximize visible resources",
                "unconventional": "accept lower apparent strength for strategic purpose",
            },
        ),
    ),

    BibleDecision(
        "judg_16_samson",
        "Judges 16",
        "Samson",
        "Samson repeatedly encounters clear signs of betrayal and danger.",
        ["withdraw and protect secret", "continue ignoring warning signs"],
        "continue ignoring warning signs",
        "bad",
        ["desire", "overconfidence", "poor risk recognition"],
        ["relationship continues"],
        ["capture, humiliation, loss of strength"],
        ["repeated_warning_signs_should_update_risk_estimate", "confidence_does_not_cancel_vulnerability"],
        tree(
            "Update behavior after repeated warning signs?",
            {
                "withdraw": "reduce exposure",
                "ignore": "continue desired behavior despite mounting evidence",
            },
        ),
    ),

    BibleDecision(
        "ruth_1_ruth",
        "Ruth 1",
        "Ruth",
        "Ruth can return to her former people or remain with Naomi.",
        ["return home", "remain with Naomi"],
        "remain with Naomi",
        "good",
        ["loyalty", "love", "commitment"],
        ["uncertain future and poverty risk"],
        ["new community, family line, restoration"],
        ["loyalty_can_outweigh_immediate_security", "relationship_commitment_can_open_unforeseen_future"],
        tree(
            "Choose familiar security or remain loyal under uncertainty?",
            {
                "return": "restore familiar life",
                "remain": "accept uncertainty for loyalty",
            },
        ),
    ),

    BibleDecision(
        "1sam_15_saul",
        "1 Samuel 15",
        "Saul",
        "Saul receives a command but preserves what he considers valuable.",
        ["obey fully", "partially obey and rationalize"],
        "partially obey and rationalize",
        "bad",
        ["self-interest", "public approval", "rationalization"],
        ["retains valuable goods"],
        ["rejection from kingship"],
        ["partial_compliance_can_mask_real_disobedience", "rationalization_is_not_correction"],
        tree(
            "Follow instruction fully or rewrite it around personal preference?",
            {
                "obey": "accept full cost",
                "partial": "retain desired benefits while claiming compliance",
            },
        ),
    ),

    BibleDecision(
        "1sam_17_david",
        "1 Samuel 17",
        "David",
        "David sees Goliath intimidating Israel.",
        ["avoid confrontation", "confront Goliath"],
        "confront Goliath",
        "good",
        ["faith", "courage", "confidence in skill"],
        ["high personal risk"],
        ["victory and changed battle outcome"],
        ["asymmetric_strategy_can_defeat_stronger_opponent", "courage_plus_skill_can_change_expected_outcome"],
        tree(
            "Accept intimidation or confront with available strengths?",
            {
                "avoid": "remain personally safe",
                "confront": "accept high risk for decisive outcome",
            },
        ),
    ),

    BibleDecision(
        "1sam_24_david_spares_saul",
        "1 Samuel 24",
        "David",
        "David has an opportunity to kill Saul while Saul is vulnerable.",
        ["kill Saul", "spare Saul"],
        "spare Saul",
        "good",
        ["restraint", "respect", "refusal of revenge"],
        ["gives up immediate tactical advantage"],
        ["demonstrates integrity and temporarily de-escalates conflict"],
        ["ability_to_harm_is_not_permission_to_harm", "restraint_can_be_strategic_and_moral"],
        tree(
            "Use opportunity for revenge or exercise restraint?",
            {
                "kill": "remove threat immediately",
                "spare": "retain principle despite tactical opportunity",
            },
        ),
    ),

    BibleDecision(
        "2sam_11_david_bathsheba",
        "2 Samuel 11",
        "David",
        "David desires Bathsheba and later attempts to conceal the resulting wrongdoing.",
        ["restrain desire", "take Bathsheba", "confess", "conceal through further wrongdoing"],
        "take Bathsheba and arrange Uriah's death",
        "bad",
        ["desire", "abuse of power", "fear of exposure"],
        ["temporary concealment"],
        ["family and national tragedy", "judgment"],
        ["one_wrong_choice_can_trigger_cover_up_chain", "power_increases_responsibility_not_permission"],
        tree(
            "Respond to desire and exposure with restraint, confession, or escalation?",
            {
                "restrain": "prevent initial wrongdoing",
                "confess": "accept consequences and stop escalation",
                "conceal": "compound wrongdoing to preserve image",
            },
        ),
    ),

    BibleDecision(
        "2sam_12_david_repents",
        "2 Samuel 12",
        "David",
        "Nathan confronts David with his wrongdoing.",
        ["deny", "blame others", "admit wrongdoing"],
        "admit wrongdoing",
        "good",
        ["repentance", "acceptance of responsibility"],
        ["loss of self-protective denial"],
        ["relationship with God continues though consequences remain"],
        ["admission_is_better_than_defensive_denial", "repentance_does_not_erase_all_consequences"],
        tree(
            "When confronted, defend ego or admit wrongdoing?",
            {
                "deny": "protect image temporarily",
                "blame": "shift responsibility",
                "admit": "accept responsibility and begin correction",
            },
        ),
    ),

    BibleDecision(
        "1kings_3_solomon",
        "1 Kings 3",
        "Solomon",
        "Solomon is invited to ask for what he wants.",
        ["ask for wealth", "ask for long life", "ask for victory", "ask for wisdom"],
        "ask for wisdom",
        "good",
        ["responsibility", "humility", "desire to govern well"],
        ["forgoes obvious material request"],
        ["receives wisdom and additional blessing"],
        ["capability_can_be_more_valuable_than_resources", "ask_for_tool_that_improves_many_future_decisions"],
        tree(
            "Choose immediate resource or decision-making capacity?",
            {
                "wealth": "gain direct resources",
                "power": "gain external advantage",
                "wisdom": "improve future judgment across many problems",
            },
        ),
    ),

    BibleDecision(
        "1kings_11_solomon",
        "1 Kings 11",
        "Solomon",
        "Solomon increasingly compromises his covenant loyalty.",
        ["maintain covenant loyalty", "follow competing influences"],
        "follow competing influences",
        "bad",
        ["attachment", "political/social influence", "compromise"],
        ["short-term relational/political accommodation"],
        ["kingdom instability and judgment"],
        ["small_compromises_can_accumulate", "success_does_not_remove_need_for_guardrails"],
        tree(
            "Maintain core commitments or gradually compromise them?",
            {
                "maintain": "preserve long-term integrity",
                "compromise": "gain immediate accommodation but weaken foundation",
            },
        ),
    ),

    BibleDecision(
        "1kings_18_elijah",
        "1 Kings 18",
        "Elijah",
        "Elijah confronts widespread idolatry and the prophets of Baal.",
        ["remain silent", "publicly confront"],
        "publicly confront",
        "good",
        ["faith", "courage", "public responsibility"],
        ["personal danger"],
        ["public demonstration and decision point for Israel"],
        ["silence_is_also_a_choice", "public_error_may_require_public_challenge"],
        tree(
            "Remain safe and silent or confront a public wrong?",
            {
                "silent": "reduce personal risk",
                "confront": "accept risk to force clarification",
            },
        ),
    ),

    BibleDecision(
        "1kings_21_ahab_jezebel",
        "1 Kings 21",
        "Ahab and Jezebel",
        "Ahab wants Naboth's vineyard, which Naboth refuses to sell.",
        ["accept refusal", "negotiate lawfully", "abuse power to seize it"],
        "abuse power to seize it",
        "bad",
        ["greed", "entitlement", "abuse of authority"],
        ["acquires the vineyard"],
        ["judgment and condemnation"],
        ["desire_does_not_create_entitlement", "power_abuse_can_make_private_greed_systemic"],
        tree(
            "Respect another person's rights or use power to override them?",
            {
                "respect": "accept denied desire",
                "negotiate": "seek lawful alternative",
                "seize": "gain object through injustice",
            },
        ),
    ),

    BibleDecision(
        "2kings_5_naaman",
        "2 Kings 5",
        "Naaman",
        "Naaman is told to follow a simple healing instruction that offends his expectations.",
        ["reject because it seems beneath him", "follow the simple instruction"],
        "follow the simple instruction",
        "good",
        ["humility", "willingness to revise expectation"],
        ["swallows pride"],
        ["healing"],
        ["simple_solution_can_be_correct_even_if_it_offends_ego", "do_not_confuse_complexity_with_value"],
        tree(
            "Reject a simple solution or try it despite wounded pride?",
            {
                "reject": "protect ego",
                "obey": "test the low-cost instruction and gain result",
            },
        ),
    ),

    BibleDecision(
        "2kings_5_gehazi",
        "2 Kings 5",
        "Gehazi",
        "Gehazi sees an opportunity to secretly gain wealth from Naaman.",
        ["respect Elisha's refusal", "lie to obtain gifts"],
        "lie to obtain gifts",
        "bad",
        ["greed", "deception"],
        ["material gain"],
        ["exposure and punishment"],
        ["secret_profit_can_destroy_trust", "lying_for_gain_creates_compounding_risk"],
        tree(
            "Accept no reward or manufacture a false reason to profit?",
            {
                "accept refusal": "forego wealth",
                "deceive": "gain short-term wealth at ethical and reputational cost",
            },
        ),
    ),

    BibleDecision(
        "esther_4_7",
        "Esther 4–7",
        "Esther",
        "Esther can remain silent or risk approaching the king to protect her people.",
        ["remain silent", "approach the king"],
        "approach the king",
        "good",
        ["courage", "responsibility", "protection of others"],
        ["risk of death"],
        ["plot exposed and people preserved"],
        ["high_personal_risk_can_be_justified_by_protecting_many", "privileged_position_can_create_responsibility"],
        tree(
            "Protect self through silence or accept risk to protect others?",
            {
                "silent": "reduce immediate personal risk",
                "act": "risk self for wider protection",
            },
        ),
    ),

    BibleDecision(
        "job_perseverance",
        "Job",
        "Job",
        "Job suffers severe unexplained loss and wrestles with God.",
        ["abandon faith entirely", "continue seeking understanding"],
        "continue seeking understanding",
        "good/complex",
        ["perseverance", "honesty", "faith amid uncertainty"],
        ["continued struggle without easy explanation"],
        ["restoration and deeper perspective"],
        ["lack_of_explanation_does_not_require_abandoning_all_commitment", "honest_questioning_can_coexist_with_faith"],
        tree(
            "What should be done when suffering has no clear explanation?",
            {
                "abandon": "end trust because explanation is absent",
                "continue": "remain engaged while questioning honestly",
            },
        ),
    ),

    BibleDecision(
        "jonah_1",
        "Jonah 1",
        "Jonah",
        "Jonah is called to go to Nineveh.",
        ["go to Nineveh", "run away"],
        "run away",
        "bad",
        ["avoidance", "resentment", "fear"],
        ["temporary escape attempt"],
        ["storm, crisis, forced course correction"],
        ["avoidance_can_increase_cost_of_eventual_task", "running_from_responsibility_is_still_a_decision"],
        tree(
            "Accept difficult responsibility or flee it?",
            {
                "accept": "face difficult mission directly",
                "flee": "delay mission and create secondary crisis",
            },
        ),
    ),

    BibleDecision(
        "jonah_3_nineveh",
        "Jonah 3",
        "People of Nineveh",
        "Nineveh receives warning of coming judgment.",
        ["ignore warning", "repent and change behavior"],
        "repent and change behavior",
        "good",
        ["humility", "fear", "course correction"],
        ["abandon previous behavior"],
        ["judgment is withheld"],
        ["warning_should_enable_course_correction", "future_consequence_can_change_when_behavior_changes"],
        tree(
            "Ignore warning or change course?",
            {
                "ignore": "continue present trajectory",
                "repent": "alter behavior to change likely outcome",
            },
        ),
    ),

    BibleDecision(
        "dan_1_daniel_food",
        "Daniel 1",
        "Daniel",
        "Daniel is pressured to eat food he believes would compromise him.",
        ["comply silently", "request an alternative"],
        "request an alternative",
        "good",
        ["conviction", "diplomacy", "self-discipline"],
        ["social and institutional risk"],
        ["alternative is accepted and Daniel prospers"],
        ["principle_and_diplomacy_can_coexist", "seek_low_conflict_alternative_before_open_defiance"],
        tree(
            "Compromise conviction or request a workable alternative?",
            {
                "comply": "reduce immediate friction",
                "alternative": "preserve conviction while minimizing conflict",
            },
        ),
    ),

    BibleDecision(
        "dan_3_furnace",
        "Daniel 3",
        "Shadrach, Meshach, and Abednego",
        "They are ordered to worship an idol under threat of death.",
        ["comply", "refuse"],
        "refuse",
        "good",
        ["faith", "integrity", "courage"],
        ["thrown into furnace"],
        ["deliverance and public vindication"],
        ["some_commitments_are_nonnegotiable", "threat_does_not_make_false_worship_true"],
        tree(
            "Preserve life by violating conviction or remain faithful?",
            {
                "comply": "avoid immediate punishment",
                "refuse": "accept extreme risk for integrity",
            },
        ),
    ),

    BibleDecision(
        "dan_6_prayer",
        "Daniel 6",
        "Daniel",
        "A law forbids Daniel's regular prayer.",
        ["stop praying", "continue praying"],
        "continue praying",
        "good",
        ["faith", "consistency", "integrity"],
        ["legal danger and lions' den"],
        ["deliverance and vindication"],
        ["temporary_law_does_not_automatically_override_core_conviction", "consistency_under_pressure_builds_integrity"],
        tree(
            "Alter core practice under coercion or remain consistent?",
            {
                "stop": "avoid immediate penalty",
                "continue": "maintain conviction despite risk",
            },
        ),
    ),

    BibleDecision(
        "matt_4_jesus_temptation",
        "Matthew 4",
        "Jesus",
        "Jesus faces temptations involving appetite, spectacle, and power.",
        ["accept shortcut", "reject temptation"],
        "reject temptation",
        "good",
        ["faithfulness", "self-control", "refusal of shortcut"],
        ["foregoes immediate relief and power"],
        ["mission continues without compromise"],
        ["do_not_trade_mission_for_shortcut", "power_without_integrity_is_not_success"],
        tree(
            "Use a shortcut that violates mission or remain faithful?",
            {
                "shortcut": "gain immediate benefit",
                "reject": "retain mission integrity",
            },
        ),
    ),

    BibleDecision(
        "matt_4_peter_andrew",
        "Matthew 4",
        "Peter and Andrew",
        "They are called to leave their nets and follow Jesus.",
        ["remain with current livelihood", "follow"],
        "follow",
        "good",
        ["faith", "calling", "willingness to change identity"],
        ["leave familiar occupation"],
        ["become disciples"],
        ["major_transition_can_require_leaving_known_role", "calling_can_outweigh_current_security"],
        tree(
            "Keep existing life or answer new calling?",
            {
                "stay": "retain established livelihood",
                "follow": "accept uncertainty and transformation",
            },
        ),
    ),

    BibleDecision(
        "matt_14_peter_water",
        "Matthew 14",
        "Peter",
        "Peter steps out of the boat toward Jesus, then becomes afraid.",
        ["stay in boat", "step out", "focus on fear and sink"],
        "step out, then fear",
        "good/complex",
        ["faith", "courage", "later fear"],
        ["brief success followed by sinking"],
        ["rescue and lesson about wavering trust"],
        ["initial_courage_can_be_undermined_by_attention_shift", "fear_after_commitment_can_change_performance"],
        tree(
            "Remain safe, commit, or abandon confidence mid-action?",
            {
                "stay": "avoid risk",
                "step": "act in faith",
                "fear": "lose stability after beginning well",
            },
        ),
    ),

    BibleDecision(
        "matt_18_unforgiving_servant",
        "Matthew 18",
        "Unforgiving servant",
        "A servant receives extraordinary mercy but later confronts someone who owes him much less.",
        ["extend mercy", "demand repayment harshly"],
        "demand repayment harshly",
        "bad",
        ["self-interest", "double standard"],
        ["recovers control over debtor"],
        ["his own mercy is revoked in the parable"],
        ["apply_mercy_consistently", "receiving_grace_should_change_how_you_treat_others"],
        tree(
            "After receiving mercy, extend it or apply a harsher standard?",
            {
                "extend": "act consistently with received mercy",
                "demand": "use a double standard",
            },
        ),
    ),

    BibleDecision(
        "matt_19_rich_young_ruler",
        "Matthew 19",
        "Rich young ruler",
        "He is challenged to relinquish wealth and follow Jesus.",
        ["retain wealth", "release wealth and follow"],
        "retain wealth",
        "bad/tragic",
        ["attachment", "security", "material dependence"],
        ["keeps possessions"],
        ["walks away sorrowful from the desired path"],
        ["attachment_can_block_declared_goal", "identify_what_you_are_unwilling_to_release"],
        tree(
            "Keep the thing providing security or pursue the higher stated goal?",
            {
                "keep": "retain immediate security",
                "release": "accept loss for larger commitment",
            },
        ),
    ),

    BibleDecision(
        "matt_20_vineyard",
        "Matthew 20",
        "Early vineyard workers",
        "Workers compare their pay with workers hired later.",
        ["accept agreed reward", "resent generosity to others"],
        "resent generosity to others",
        "bad",
        ["comparison", "envy", "entitlement"],
        ["dissatisfaction despite receiving agreed wage"],
        ["lesson about generosity and comparison"],
        ["comparison_can_turn_sufficient_reward_into_resentment", "another_persons_gain_is_not_automatically_your_loss"],
        tree(
            "Evaluate your outcome by agreement or by comparison with others?",
            {
                "agreement": "judge outcome by what was fairly promised",
                "comparison": "become dissatisfied because another received generosity",
            },
        ),
    ),

    BibleDecision(
        "matt_25_bridesmaids",
        "Matthew 25",
        "Wise bridesmaids",
        "The bridesmaids do not know exactly when the bridegroom will arrive.",
        ["prepare extra oil", "assume timing will be convenient"],
        "prepare extra oil",
        "good",
        ["preparedness", "foresight"],
        ["carry additional supplies"],
        ["ready when delay occurs"],
        ["prepare_for_uncertain_timing", "small_redundancy_can_prevent_large_failure"],
        tree(
            "Prepare for delay or optimize only for expected timing?",
            {
                "prepare": "carry reserve capacity",
                "minimum": "risk failure if timing changes",
            },
        ),
    ),

    BibleDecision(
        "matt_25_one_talent",
        "Matthew 25",
        "Servant with one talent",
        "A servant must decide what to do with entrusted resources.",
        ["use the resource", "hide it out of fear"],
        "hide it out of fear",
        "bad",
        ["fear", "risk avoidance"],
        ["avoids immediate loss"],
        ["fails to produce value and is condemned in the parable"],
        ["excessive_risk_avoidance_can_be_a_failure", "unused_capacity_can_decay_in_value"],
        tree(
            "Use entrusted capacity or bury it to avoid risk?",
            {
                "use": "accept measured risk for growth",
                "hide": "eliminate action risk but also eliminate productive outcome",
            },
        ),
    ),

    BibleDecision(
        "matt_26_judas",
        "Matthew 26",
        "Judas",
        "Judas chooses whether to betray Jesus.",
        ["remain loyal", "betray"],
        "betray",
        "bad",
        ["money", "disillusionment or mixed motives"],
        ["receives payment"],
        ["catastrophic guilt and death"],
        ["betrayal_for_short_term_gain_can_create_irreversible_loss"],
        tree(
            "Remain loyal or exchange relationship for short-term gain?",
            {
                "loyal": "preserve relationship and commitment",
                "betray": "obtain immediate gain at enormous moral cost",
            },
        ),
    ),

    BibleDecision(
        "matt_26_peter_denial",
        "Matthew 26",
        "Peter",
        "Peter is questioned about association with Jesus while afraid.",
        ["admit association", "deny"],
        "deny",
        "bad",
        ["fear", "self-preservation"],
        ["avoids immediate identification"],
        ["deep regret"],
        ["fear_can_override_declared_commitment", "prepare_for_pressure_before_it_arrives"],
        tree(
            "Preserve safety through denial or maintain loyalty under pressure?",
            {
                "admit": "accept danger",
                "deny": "reduce immediate risk but violate commitment",
            },
        ),
    ),

    BibleDecision(
        "matt_27_pilate",
        "Matthew 27",
        "Pilate",
        "Pilate faces pressure to condemn Jesus despite recognizing the case is problematic.",
        ["resist crowd pressure", "yield to expediency"],
        "yield to expediency",
        "bad",
        ["political pressure", "self-preservation", "expediency"],
        ["avoids immediate unrest"],
        ["participates in injustice"],
        ["social_pressure_does_not_remove_responsibility", "expediency_can_be_morally_catastrophic"],
        tree(
            "Do what appears just or surrender judgment to political pressure?",
            {
                "resist": "accept unrest or political cost",
                "yield": "gain short-term stability at cost of justice",
            },
        ),
    ),

    BibleDecision(
        "luke_10_priest_levite",
        "Luke 10",
        "Priest and Levite",
        "They encounter an injured man on the road.",
        ["stop and help", "pass by"],
        "pass by",
        "bad",
        ["avoidance", "self-protection", "possible ritual/social concerns"],
        ["save time and avoid involvement"],
        ["fail the neighbor-love test of the parable"],
        ["convenience_does_not_cancel_duty_to_help", "inaction_is_still_a_choice"],
        tree(
            "Become involved in another person's need or preserve convenience?",
            {
                "help": "accept time, cost, and risk",
                "pass": "avoid cost while leaving need unmet",
            },
        ),
    ),

    BibleDecision(
        "luke_10_samaritan",
        "Luke 10",
        "Good Samaritan",
        "A Samaritan encounters the same injured man.",
        ["pass by", "help"],
        "help",
        "good",
        ["compassion", "neighbor-love"],
        ["time, money, and personal inconvenience"],
        ["injured man receives care"],
        ["helpfulness_can_outweigh_inconvenience", "moral_neighbor_is_defined_by_action_not_group"],
        tree(
            "Ignore a stranger's need or absorb cost to help?",
            {
                "pass": "preserve resources",
                "help": "spend resources to reduce another person's suffering",
            },
        ),
    ),

    BibleDecision(
        "luke_15_prodigal_leave",
        "Luke 15",
        "Prodigal son",
        "The son receives his inheritance and decides how to use it.",
        ["manage it responsibly", "waste it"],
        "waste it",
        "bad",
        ["impulse", "desire for independence", "short-term pleasure"],
        ["temporary pleasure"],
        ["poverty and crisis"],
        ["resource_without_discipline_can_disappear", "short_term_freedom_can_create_long_term_dependency"],
        tree(
            "Steward resources or consume them impulsively?",
            {
                "steward": "preserve future options",
                "waste": "maximize immediate experience at future cost",
            },
        ),
    ),

    BibleDecision(
        "luke_15_prodigal_return",
        "Luke 15",
        "Prodigal son",
        "After failure, the son can remain in ruin or return home.",
        ["stay away out of shame", "return and admit wrongdoing"],
        "return and admit wrongdoing",
        "good",
        ["humility", "repentance", "course correction"],
        ["accepts shame and uncertainty"],
        ["reconciliation and restoration"],
        ["past_failure_does_not_make_course_correction_irrational", "admit_failure_early_and_return"],
        tree(
            "Persist in failed path because of shame or reverse course?",
            {
                "persist": "avoid immediate humiliation",
                "return": "accept humility for possible restoration",
            },
        ),
    ),

    BibleDecision(
        "luke_15_older_brother",
        "Luke 15",
        "Older brother",
        "The older brother sees the celebration for his returning brother.",
        ["join reconciliation", "resent the mercy shown"],
        "resent the mercy shown",
        "bad/complex",
        ["comparison", "self-righteousness", "resentment"],
        ["withdraws from celebration"],
        ["alienation from father and brother"],
        ["another_persons_restoration_is_not_your_loss", "fairness_without_mercy_can_become_resentment"],
        tree(
            "Celebrate restoration or interpret mercy as personal unfairness?",
            {
                "celebrate": "join repaired relationship",
                "resent": "preserve grievance and remain outside reconciliation",
            },
        ),
    ),

    BibleDecision(
        "luke_19_zacchaeus",
        "Luke 19",
        "Zacchaeus",
        "Zacchaeus responds to his changed understanding of his conduct.",
        ["make verbal promises only", "make restitution"],
        "make restitution",
        "good",
        ["repentance", "justice", "repair"],
        ["material loss"],
        ["demonstrates concrete change"],
        ["real_change_should_have_observable_cost", "repair_harm_not_just_intention"],
        tree(
            "Express regret only or materially repair prior harm?",
            {
                "words": "low-cost expression",
                "restitution": "accept cost to repair damage",
            },
        ),
    ),

    BibleDecision(
        "luke_22_jesus_gethsemane",
        "Luke 22",
        "Jesus",
        "Jesus faces arrest and suffering.",
        ["flee", "resist mission", "submit to the path ahead"],
        "submit to the path ahead",
        "good",
        ["obedience", "sacrifice", "mission fidelity"],
        ["arrest and suffering"],
        ["central redemptive outcome in Christian theology"],
        ["mission_fidelity_can_require_personal_cost", "fear_does_not_make_retreat_mandatory"],
        tree(
            "Escape suffering or remain committed to mission?",
            {
                "flee": "avoid immediate suffering",
                "submit": "accept suffering for larger purpose",
            },
        ),
    ),

    BibleDecision(
        "luke_23_criminal",
        "Luke 23",
        "Criminal beside Jesus",
        "A condemned criminal can mock, remain indifferent, or turn toward Jesus.",
        ["mock", "remain indifferent", "turn toward Jesus"],
        "turn toward Jesus",
        "good",
        ["repentance", "faith"],
        ["no change to earthly sentence"],
        ["promise of paradise"],
        ["course_correction_can_still_matter_late", "not_all_value_is_immediate"],
        tree(
            "What should be done when almost no time remains?",
            {
                "mock": "continue rejection",
                "ignore": "make no change",
                "turn": "change allegiance despite no earthly advantage",
            },
        ),
    ),

    BibleDecision(
        "john_8_accusers",
        "John 8",
        "Accusers",
        "A group seeks condemnation of a woman while ignoring their own moral failures.",
        ["self-examine", "condemn while claiming superiority"],
        "seek condemnation",
        "bad",
        ["hypocrisy", "public judgment"],
        ["attempt to punish another"],
        ["accusers withdraw under self-examination"],
        ["apply_standard_to_self_before_others", "certainty_about_others_can_hide_self_blindness"],
        tree(
            "Condemn another immediately or examine one's own standing first?",
            {
                "self-examine": "reduce hypocrisy and increase humility",
                "condemn": "apply asymmetrical moral standard",
            },
        ),
    ),

    BibleDecision(
        "john_11_thomas",
        "John 11",
        "Thomas",
        "Jesus intends to return toward danger after Lazarus dies.",
        ["avoid danger", "go with Jesus"],
        "go with Jesus",
        "good",
        ["loyalty", "courage despite pessimism"],
        ["accepts perceived mortal danger"],
        ["remains with the group"],
        ["loyal_action_can_exist_even_without_optimism", "courage_is_not_the_same_as_confidence"],
        tree(
            "Avoid danger or remain loyal despite expecting the worst?",
            {
                "avoid": "reduce personal risk",
                "go": "accept risk for loyalty",
            },
        ),
    ),

    BibleDecision(
        "john_12_mary",
        "John 12",
        "Mary",
        "Mary possesses expensive perfume and chooses how to use it.",
        ["retain or sell it", "anoint Jesus"],
        "anoint Jesus",
        "good",
        ["devotion", "love", "symbolic understanding"],
        ["large material cost"],
        ["act is remembered as devotion"],
        ["not_all_value_is_financial", "symbolic_action_can_have_meaning_beyond_efficiency"],
        tree(
            "Optimize material value or spend it on devotion?",
            {
                "retain": "preserve financial value",
                "anoint": "accept material cost for symbolic purpose",
            },
        ),
    ),

    BibleDecision(
        "john_18_peter_sword",
        "John 18",
        "Peter",
        "During Jesus' arrest, Peter chooses whether to use violence.",
        ["remain restrained", "attack with sword"],
        "attack with sword",
        "bad",
        ["fear", "loyalty expressed impulsively", "violence"],
        ["injury to servant"],
        ["Jesus stops and reverses the harm"],
        ["good_intention_does_not_validate_wrong_tactic", "impulsive_force_can_oppose_the_goal_you_mean_to_defend"],
        tree(
            "Respond to threat with restraint or impulsive violence?",
            {
                "restrain": "remain aligned with nonviolent mission",
                "attack": "attempt immediate defense but conflict with mission",
            },
        ),
    ),

    BibleDecision(
        "john_20_thomas",
        "John 20",
        "Thomas",
        "Thomas hears testimony that Jesus has risen.",
        ["accept testimony immediately", "seek evidence", "refuse permanently"],
        "seek evidence and later believe",
        "complex",
        ["skepticism", "desire for verification"],
        ["delay in belief"],
        ["belief after encounter"],
        ["verification_can_be_part_of_belief_revision", "doubt_need_not_be_permanent_refusal"],
        tree(
            "How should uncertain testimony be handled?",
            {
                "accept": "trust testimony immediately",
                "verify": "seek evidence and remain open to revision",
                "refuse": "close possibility regardless of evidence",
            },
        ),
    ),

    BibleDecision(
        "acts_5_ananias_sapphira",
        "Acts 5",
        "Ananias and Sapphira",
        "They sell property and decide how to represent the proceeds.",
        ["state honestly what they are giving", "lie about the amount"],
        "lie about the amount",
        "bad",
        ["reputation", "deception", "desire to appear more generous"],
        ["retain some wealth while claiming full sacrifice"],
        ["judgment"],
        ["image_management_can_motivate_deception", "false_signal_of_sacrifice_is_not_real_sacrifice"],
        tree(
            "Represent contribution honestly or exaggerate virtue through deception?",
            {
                "honest": "retain freedom while telling truth",
                "lie": "gain reputation while hiding reality",
            },
        ),
    ),

    BibleDecision(
        "acts_7_stephen",
        "Acts 7",
        "Stephen",
        "Stephen is being killed by an angry crowd.",
        ["curse attackers", "seek revenge", "forgive"],
        "forgive",
        "good",
        ["mercy", "faith"],
        ["no immediate rescue"],
        ["models forgiveness under extreme harm"],
        ["mercy_can_be_chosen_even_when_outcome_cannot_be_changed", "do_not_let_attackers_determine_your_final_character"],
        tree(
            "Respond to irreversible harm with hatred or mercy?",
            {
                "hate": "mirror hostility",
                "forgive": "refuse final retaliation",
            },
        ),
    ),

    BibleDecision(
        "acts_8_simon",
        "Acts 8",
        "Simon",
        "Simon sees spiritual authority and wants to obtain it.",
        ["receive correction humbly", "attempt to purchase authority"],
        "attempt to purchase authority",
        "bad",
        ["status", "power", "transactional thinking"],
        ["attempts to convert money into authority"],
        ["strong rebuke"],
        ["not_every_value_is_purchasable", "power_without_character_is_dangerous"],
        tree(
            "Treat authority as gift/responsibility or as commodity?",
            {
                "responsibility": "accept limits and formation",
                "purchase": "try to bypass formation through resources",
            },
        ),
    ),

    BibleDecision(
        "acts_9_ananias",
        "Acts 9",
        "Ananias",
        "Ananias is told to approach Saul, known for persecuting Christians.",
        ["refuse because of prior evidence", "go based on new instruction"],
        "go based on new instruction",
        "good",
        ["faith", "courage", "updating belief"],
        ["personal perceived risk"],
        ["Saul is received and assisted"],
        ["new_reliable_information_should_update_old_threat_model", "past_behavior_is_relevant_but_not_always_final"],
        tree(
            "Rely only on prior threat history or incorporate new information?",
            {
                "refuse": "maximize safety based on old model",
                "go": "accept risk because state may have changed",
            },
        ),
    ),

    BibleDecision(
        "acts_9_saul",
        "Acts 9",
        "Saul / Paul",
        "Saul is confronted with evidence that his current mission is wrong.",
        ["double down", "change course"],
        "change course",
        "good",
        ["repentance", "belief revision", "obedience"],
        ["loss of status and previous identity"],
        ["transformed mission"],
        ["strong_new_evidence_can_require_radical_model_update", "identity_should_not_block_correction"],
        tree(
            "Defend prior identity or revise course after disconfirming evidence?",
            {
                "double down": "protect ego and old mission",
                "change": "accept major identity cost to follow revised understanding",
            },
        ),
    ),

    BibleDecision(
        "acts_10_peter",
        "Acts 10",
        "Peter",
        "Peter's inherited category boundaries are challenged.",
        ["preserve old exclusion", "revise understanding and include Gentiles"],
        "revise understanding and include Gentiles",
        "good",
        ["obedience", "learning", "reassessment"],
        ["social and theological friction"],
        ["expanded inclusion"],
        ["update_categories_when_foundation_changes", "tradition_should_not_block_clear_correction"],
        tree(
            "Preserve inherited boundary or revise it after new understanding?",
            {
                "preserve": "maintain familiar model",
                "revise": "accept disruption to align with new evidence",
            },
        ),
    ),

    BibleDecision(
        "acts_15_council",
        "Acts 15",
        "Apostles and elders",
        "The early church faces disagreement over requirements for Gentile believers.",
        ["impose full prior system", "remove all standards", "deliberate and form a workable resolution"],
        "deliberate and form a workable resolution",
        "good",
        ["wisdom", "community discernment", "compromise without abandoning core beliefs"],
        ["requires debate and concession"],
        ["a shared policy is established"],
        ["conflicting_positions_can_generate_third_solution", "deliberation_can_reduce_false_binary_choices"],
        tree(
            "Choose one extreme or synthesize a principled third path?",
            {
                "full burden": "maximize continuity",
                "no structure": "maximize freedom",
                "resolution": "preserve core principles while reducing unnecessary burden",
            },
        ),
    ),

    BibleDecision(
        "acts_16_paul_silas",
        "Acts 16",
        "Paul and Silas",
        "Paul and Silas are imprisoned after being beaten.",
        ["despair", "retaliate", "continue praying and singing"],
        "continue praying and singing",
        "good",
        ["faith", "resilience", "perseverance"],
        ["remain imprisoned physically"],
        ["unexpected prison opening and influence on jailer"],
        ["maintain_internal_agency_when_external_control_is_low", "resilience_can_change_downstream_events"],
        tree(
            "When external options are restricted, surrender inner agency or preserve it?",
            {
                "despair": "allow circumstances to determine internal state",
                "persevere": "continue purposeful action within remaining freedom",
            },
        ),
    ),

    BibleDecision(
        "acts_16_jailer",
        "Acts 16",
        "Philippian jailer",
        "The jailer believes prisoners escaped and prepares to kill himself, then receives new information.",
        ["act immediately on assumption", "pause when new information arrives"],
        "pause and reverse course",
        "good",
        ["responsiveness to new information", "hope"],
        ["stops irreversible act"],
        ["survival and changed life"],
        ["verify_before_irreversible_action", "new_information_should_interrupt_catastrophic_commitment"],
        tree(
            "Commit to irreversible action based on assumption or re-check the state?",
            {
                "act": "irreversible harm based on incomplete model",
                "pause": "update from new information and preserve future options",
            },
        ),
    ),

    BibleDecision(
        "philemon_onesimus",
        "Philemon",
        "Philemon",
        "Philemon is asked to receive Onesimus not merely according to prior social status but as a brother.",
        ["punish or reduce him to prior status", "receive him relationally"],
        "receive him as a brother (the decision Paul urges)",
        "good decision proposed",
        ["forgiveness", "reconciliation", "changed relationship"],
        ["relinquishes some social leverage"],
        ["potential restoration of relationship"],
        ["reconciliation_can_require_reclassifying_relationship", "new_identity_can_change_old_power_structure"],
        tree(
            "Preserve old status relationship or receive the person under a new relational model?",
            {
                "old status": "retain hierarchy and grievance",
                "brother": "accept reconciliation and transformed relationship",
            },
        ),
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_decision(decision_id: str) -> Optional[BibleDecision]:
    for d in BIBLE_DECISIONS:
        if d.id == decision_id:
            return d
    return None


def search(
    text: str = "",
    actor: str = "",
    reference: str = "",
    classification: str = "",
    principle: str = "",
) -> List[BibleDecision]:
    results = []
    text_l = text.lower()
    actor_l = actor.lower()
    ref_l = reference.lower()
    class_l = classification.lower()
    principle_l = principle.lower()

    for d in BIBLE_DECISIONS:
        haystack = " ".join([
            d.actor,
            d.reference,
            d.situation,
            " ".join(d.options),
            d.chosen,
            " ".join(d.motives),
            " ".join(d.immediate_consequences),
            " ".join(d.delayed_consequences),
            " ".join(d.principles),
        ]).lower()

        if text_l and text_l not in haystack:
            continue
        if actor_l and actor_l not in d.actor.lower():
            continue
        if ref_l and ref_l not in d.reference.lower():
            continue
        if class_l and class_l not in d.classification.lower():
            continue
        if principle_l and not any(principle_l in p.lower() for p in d.principles):
            continue
        results.append(d)

    return results


def export_json(path: str = "bible_ndw_choices.json") -> Path:
    p = Path(path)
    p.write_text(
        json.dumps([d.to_dict() for d in BIBLE_DECISIONS], indent=2),
        encoding="utf-8",
    )
    return p


def print_tree(d: BibleDecision) -> None:
    print(f"\n[{d.reference}] {d.actor}")
    print(f"Situation: {d.situation}")
    print(f"Question: {d.tree['question']}")
    for branch, outcome in d.tree["branches"].items():
        marker = " <-- CHOSEN" if branch.lower() in d.chosen.lower() else ""
        print(f"  ├─ {branch}{marker}")
        print(f"  │    {outcome}")
    print(f"Classification: {d.classification}")
    print("Principles:")
    for p in d.principles:
        print(f"  - {p}")


def print_all_trees() -> None:
    for d in BIBLE_DECISIONS:
        print_tree(d)


# ---------------------------------------------------------------------------
# NDW adapter
# ---------------------------------------------------------------------------

def load_into_ndw(ndw) -> Dict[str, int]:
    """
    Load this corpus into the NDW engine from modules.narrative_decision_weave.

    Expected NDW API:
        ndw.add_pattern(...)
        Action(...)
        Consequence(...)

    Example:
        from modules.narrative_decision_weave import NarrativeDecisionWeave
        from modules.bible_ndw_choices import load_into_ndw

        engine = NarrativeDecisionWeave()
        load_into_ndw(engine)
    """
    try:
        from modules.narrative_decision_weave import Action, Consequence
    except ImportError as exc:
        raise ImportError(
            "Import modules.narrative_decision_weave before loading the Bible NDW corpus."
        ) from exc

    existing_ids = {
        pattern.abstract_roles.get("decision_id")
        for pattern in ndw.patterns
        if pattern.abstract_roles.get("dataset") == "bible_ndw"
    }
    loaded = 0
    skipped = 0

    for d in BIBLE_DECISIONS:
        if d.id in existing_ids:
            skipped += 1
            continue

        actions = []
        consequences = []

        for i, option in enumerate(d.options):
            name = f"OPTION_{i+1}"
            actions.append(
                Action(
                    name=name,
                    description=option,
                    tags=list(d.principles),
                )
            )

            if option.lower() in d.chosen.lower() or d.chosen.lower() in option.lower():
                effect = 1.0 if d.classification.startswith("good") else -1.0
                consequences.append(
                    Consequence(
                        action_name=name,
                        next_state="; ".join(
                            d.immediate_consequences + d.delayed_consequences
                        ),
                        effects={"goal_progress": effect},
                        confidence=0.80,
                    )
                )
            else:
                consequences.append(
                    Consequence(
                        action_name=name,
                        next_state="counterfactual branch not explicitly narrated",
                        effects={},
                        confidence=0.25,
                    )
                )

        ndw.add_pattern(
            source_label=f"{d.reference} | {d.actor}",
            situation=d.situation,
            actions=actions,
            consequences=consequences,
            abstract_roles={
                "actor": d.actor,
                "source": d.reference,
                "dataset": "bible_ndw",
                "decision_id": d.id,
            },
            concepts=d.principles + d.motives,
            notes=(
                f"Classification: {d.classification}. "
                f"Chosen action: {d.chosen}. "
                f"Immediate: {'; '.join(d.immediate_consequences)}. "
                f"Delayed: {'; '.join(d.delayed_consequences)}."
            ),
        )
        loaded += 1

    return {
        "total": len(BIBLE_DECISIONS),
        "loaded": loaded,
        "skipped": skipped,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"Bible NDW corpus loaded: {len(BIBLE_DECISIONS)} decision nodes")
    print()
    print("Examples:")
    print("  python bible_ndw_choices.py")
    print("  python -c \"from bible_ndw_choices import export_json; print(export_json())\"")
    print("  python -c \"from bible_ndw_choices import search; print(search(actor='Joseph'))\"")
    print()
    print("First 5 decision trees:")
    for d in BIBLE_DECISIONS[:5]:
        print_tree(d)


if __name__ == "__main__":
    main()
