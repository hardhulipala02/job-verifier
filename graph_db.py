import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

class Neo4jAgent:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI"),
            auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD"))
        )

    def close(self):
        self.driver.close()

    def add_scam_report(self, scorecard, sender, domain):
        with self.driver.session() as session:
            session.execute_write(self._create_report_nodes, scorecard, sender, domain)
            print("Successfully pushed scam report to Graph DB!")

    @staticmethod
    def _create_report_nodes(tx, scorecard, sender, domain):
        query = """
        MERGE (d:Domain {name: $domain})
        MERGE (r:Recruiter {name: $sender})
        MERGE (r)-[:USES_DOMAIN]->(d)
        SET r.risk = $risk, r.summary = $summary
        """
        tx.run(query, domain=domain, sender=sender, 
               risk=scorecard['risk_level'], summary=scorecard['summary'])

if __name__ == "__main__":
    db = Neo4jAgent()
    # Mock data to test your first node creation
    mock_scorecard = {"risk_level": "HIGH", "summary": "Detected Telegram trap"}
    db.add_scam_report(mock_scorecard, "Anne", "XXXX")
    db.close()