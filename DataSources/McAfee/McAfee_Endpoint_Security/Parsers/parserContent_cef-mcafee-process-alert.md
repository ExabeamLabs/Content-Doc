#### Parser Content
```Java
{
Name = cef-mcafee-process-alert
  DataType = "process-alert"
  IsHVF = true
  Conditions = [ """CEF:""", """|McAfee|ePolicy Orchestrator|""", """Access Protection rule violation detected and """ ]
  Fields = ${McAfeeParserTemplates.cef-mcafee-epo-alert.Fields}[
    """Access Protection rule violation detected and ({outcome}(NOT )?blocked)""",
    """\sshost=(_|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\ssrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\ssproc=({process}({directory}[^=]*?[\\\/]+)?({process_name}[^=\\\/]+))(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```