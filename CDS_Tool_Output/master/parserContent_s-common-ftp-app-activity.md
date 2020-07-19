#### Parser Content
```Java
{
Name = s-common-ftp-app-activity
  Conditions = [ """]UNDEFINED """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-1
  Conditions = [ """]user """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-2
  Conditions = [ """]ssh_disconnect """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-3
  Conditions = [ """]list """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-4
  Conditions = [ """]size """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-5
  Conditions = [ """]mkd """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-6
  Conditions = [ """]quit """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-7
  Conditions = [ """]kick """ ]
}

${UnixParserTemplates.s-common-ftp-app-activity}{
  Name = s-common-ftp-app-activity-8
  Conditions = [ """]retr """ ]
}
${UnixParserTemplates.cds-user-activity}{
  Name = cds-account-auth
  Conditions = [ """AUDIT:""", """ uid=""", """type=USER_AUTH""" ]
  DataType = "remote-logon"
}
${UnixParserTemplates.cds-user-activity}{
  Name = cds-user-login
  Conditions = [ """AUDIT:""", """ uid=""", """type=USER_LOGIN""" ]
  DataType = "remote-logon"
}

{
  Name = raw-unix-process-created
  Vendor = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """; USER=""", """; COMMAND=""" ]
  Fields = [
    """({time}\w+ \d+ \d\d:\d\d:\d\d)\s*:\s*({user}[^:]+?)\s*:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """; USER=({account}[^;]+?)\s*;""",
    """; COMMAND=({command_line}[^;]+?)\s*(;|$|")""",
    """; COMMAND=({process}({process_directory}[^\s]+[\\\/]+)?({process_name}[^";\\\/\s]+))[\s"](?:|;|$)"""
  ]
  DupFields = [ "process_directory->directory","host->dest_host" ]
}
```