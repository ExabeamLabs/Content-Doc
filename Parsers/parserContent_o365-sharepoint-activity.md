#### Parser Content
```Java
{
Name = o365-sharepoint-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """SharePoint""", """ItemType""" ]
  Fields = [
    """"CreationTime\\*"+:\\*\s*"+({time}[^\\"]+)""",
    """exabeam_host=({host}[^\s]+)""",
    """"host\\*"+:\\*\s*"+({host}[^"\\]+)""",
    """"SourceRelativeUrl\\*"+:\\*\s*"+({file_parent}[^"]+)""",
    """"ObjectId\\*"+:\\*\s*"+({file_path}[^"]+)[\\"](?!\\u\d+)""",
    """"ObjectId\\*"+:\\*\s*"+({file_parent}[^"]+)[\\\/](?!u\d+)""",
    """"ObjectId\\*"+:\\*\s*"+[^"]*?({file_name}[^\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)"(?!u\d+)""",
    """"Operation\\*"+:\\*\s*"+({accesses}[^"\\]+)""",
    """"UserId\\*"+:\\*\s*"+({user_email}[^"@]+@({email_domain}[^@"\\]+))""",
    """"UserId\\*"+:\\*\s*"+(Teams Meeting Anonymous Participant|(({domain}[^\\\s@"]+)\\+)?({user}[^\\\s@"]+)\s)""",
    """"ClientIP\\*"+:\\*\s*"+({src_ip}[a-fA-F:\d.]+)""",
    """"UserAgent\\*"+:\\*\s*"+({user_agent}[^"\\]+)"+,""",
    """"UserSharedWith\\*"+:\\*\s*"+({object}[^"@\\]+)""",
    """"SourceFileName\\*"+:\\*\s*"+\s*({file_name}[^"\\]+?)\s*"""",
    """"SourceFileExtension\\*"+:\\*\s*"+({file_ext}[^"\\,]+)"""",
    """"ItemType\\*"+:\\*\s*"+({file_type}[^"\\]+)""",
    """"Workload\\*"+:\\*\s*"+({app}[^"\\]+)""",
    """"NewValue\\*"+:\\*\s*"+({object}[^"@\\]+)""",
    """\WfilePath=\{.*?"ObjectUrl":"({file_path}[^"]+)"""",
    """\WfileType=({file_type}[^\s]+)""",
    """\Wsproc=(|({user_email}.+?))(\s+\w+=|\s*$)""",
    """\WfilePermission=(|({permission_type}.+?))(\s+\w+=|\s*$)""",
    """\Wduser=(|({action_performer}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|({affected_user}[^@\s]+@.+?))(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "accesses->activity" ]
}
```