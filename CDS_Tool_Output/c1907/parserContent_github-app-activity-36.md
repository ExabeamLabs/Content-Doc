#### Parser Content
```Java
{
Name = github-app-activity-36
   Conditions = [ """project.close,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-37
   Conditions = [ """org.enable_two_factor_requirement,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-38
   Conditions = [ """billing.change_email,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-39
   Conditions = [ """account.plan_change,""" ]
}

{
  Name = cef-github-app-activity
  Vendor = GitHub
  Product = GitHub
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=GitHub""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}\S+) Skyformation -""",
    """\Wsuser=({user}[^\s]+)""",
    """\WflexString1=({activity}.+?)(?:Event|)\s*(\w+=|$)""",
    """\WrequestClientApplication=({app}.+?)\s*(\w+=|$)""",
    """\Wdproc=({resource}.+?)\s*(\w+=|$)""",
    """\Wdproc=({object}.+?)\s*(\w+=|$)""",
    """\Wfname=({object}.+?)\s*(\w+=|$)""",
    """\WfileType=({additional_info}.+?)\s*(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s*(\w+=|$)""",
  ]
}
```