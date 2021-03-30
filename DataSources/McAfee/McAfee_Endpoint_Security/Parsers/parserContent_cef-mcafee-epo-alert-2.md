#### Parser Content
```Java
{
Name = cef-mcafee-epo-alert-2
  Conditions = [ """CEF""","""|McAfee|ePolicy Orchestrator|""", """The user was not authorized to access the requested URL""" ]
  Fields = ${McAfeeParserTemplates.cef-mcafee-epo-alert.Fields}[
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s+(\w+=|$)""",
    """\seventId=({alert_id}\d+)""",
    """\scatdt=({alert_type}.*?)\s+(\w+=|$)""",
  ]
}
```