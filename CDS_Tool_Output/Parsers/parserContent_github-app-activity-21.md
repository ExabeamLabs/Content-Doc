#### Parser Content
```Java
{
Name = github-app-activity-21
   Conditions = [ """org.audit_log_export,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-22
   Conditions = [ """team.rename,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-23
   Conditions = [ """team.remove_repository,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-24
   Conditions = [ """team.delete,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-25
   Conditions = [ """required_status_check.create,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-26
   Conditions = [ """protected_branch.destroy,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-27
   Conditions = [ """org.cancel_invitation,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-28
   Conditions = [ """required_status_check.destroy,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-29
   Conditions = [ """payment_method.update,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-30
   Conditions = [ """hook.config_changed,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-31
   Conditions = [ """repo.rename,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-32
   Conditions = [ """hook.create,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-33
   Conditions = [ """repo.transfer,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-34
   Conditions = [ """protected_branch.update_required_status_checks_enforcement_level,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-35
   Conditions = [ """project.create,""" ]
}
${GithubParserTemplates.github-app-activity}{
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