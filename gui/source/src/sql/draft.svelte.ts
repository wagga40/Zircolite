/** The console's text, kept across views so that leaving the SQL view does not lose it. */
export const sqlDraft = $state({
  text: 'SELECT r.title, count(DISTINCT h._zl_uid) AS events\nFROM hits h JOIN rules r USING (rule_idx)\nGROUP BY r.title\nORDER BY events DESC\nLIMIT 20',
});
