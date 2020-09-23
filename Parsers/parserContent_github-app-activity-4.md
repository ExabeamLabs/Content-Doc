#### Parser Content
```Java
{
Name = github-app-activity-4
   Conditions = [ """team.remove_member,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-5
   Conditions = [ """org.add_member,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-6
   Conditions = [ """team.add_repository,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-7
   Conditions = [ """issue_comment.destroy,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-8
   Conditions = [ """team.create,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-9
   Conditions = [ """protected_branch.create,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-10
   Conditions = [ """org.remove_member,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-11
   Conditions = [ """repo.create,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-12
   Conditions = [ """team.change_privacy,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-13
   Conditions = [ """protected_branch.update_admin_enforced,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-14
   Conditions = [ """protected_branch.rejected_ref_update,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-15
   Conditions = [ """repo.remove_member,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-16
   Conditions = [ """repo.destroy,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-17
   Conditions = [ """repo.add_member,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-18
   Conditions = [ """team.change_parent_team,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-19
   Conditions = [ """org.update_member,""" ]
}
${GithubParserTemplates.github-app-activity}{
   Name = github-app-activity-20
   Conditions = [ """team.destroy,""" ]
}
${GithubParserTemplates.github-app-activity}{
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