import { behaviorEngine } from "./behavior";
import { mapAlertToMitre } from "./mitre";

class ScoringEngine {
  scoreAlert(alert: any) {
    try {
      const base = (alert.threat_score && alert.threat_score.score) || 0.5;
      const corrCount = alert._correlation_summary?.correlated_event_count || 0;
      const behaviorPatterns = (alert.behavior_analysis && alert.behavior_analysis.patterns) || [];

      // correlation factor: logarithmic bump
      const corrFactor = Math.min(0.2, Math.log(1 + corrCount) / 3);
      // behavior factor based on number of patterns
      const behFactor = Math.min(0.25, behaviorPatterns.length * 0.08);

      let newScore = base + corrFactor + behFactor;
      if (newScore > 1.0) newScore = 1.0;

      alert.threat_score = alert.threat_score || { score: base, level: "Medium", confidence: 0.5, sources: [] };
      alert.threat_score.score = parseFloat(newScore.toFixed(2));

      // derive level
      const level = alert.threat_score.score >= 0.9 ? "Critical" : alert.threat_score.score >= 0.7 ? "High" : alert.threat_score.score >= 0.45 ? "Medium" : "Low";
      alert.threat_level = level;

      // add scoring metadata
      alert.scoring = alert.scoring || {};
      alert.scoring.updated_at = new Date().toISOString();
      alert.scoring.corr_count = corrCount;
      alert.scoring.behavior_patterns = behaviorPatterns.length;

      // MITRE mapping - add technique hints for downstream export
      try {
        const mitre = mapAlertToMitre(alert);
        if (mitre && mitre.techniques.length) {
          alert.mitre_techniques = mitre.techniques;
          alert.mitre_descriptions = mitre.descriptions;
        }
      } catch (e) {
        // ignore mapping failures
      }

      return alert;
    } catch (e) {
      return alert;
    }
  }
}

export const scoringEngine = new ScoringEngine();
export default scoringEngine;
