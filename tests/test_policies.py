from swarmguard.config import TICKET_SPACE, ZONE_SPACE
from swarmguard.experiment.policies import build_actions


def test_every_scenario_has_matched_request_budget():
    for scenario in ("benign_flash","independent_recon","coordinated_swarm"):
        actions=build_actions(scenario,agent_idx=7,agent_count=100,requests_per_agent=6,seed=42,repeat=0)
        assert len(actions)==6


def test_coordinated_actions_are_bounded():
    actions=build_actions("coordinated_swarm",agent_idx=99,agent_count=100,requests_per_agent=3,seed=42,repeat=0)
    ticket=next(a for a in actions if a.family=="ticket")
    zone=next(a for a in actions if a.family=="zone")
    ticket_id=int(ticket.path.rsplit("/",1)[-1]); zone_id=int(zone.path.split("/")[4])
    assert 0<=ticket_id<TICKET_SPACE
    assert 0<=zone_id<ZONE_SPACE
