#### Parser Content
```Java
{
Name = s-exchange-app-activity
    Vendor = Microsoft
    Product = Exchange
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "dd/MM/yyyy HH:mm:ss"
    Conditions = [ """Param="""", """Identity="""", """Cmdlet="""" ]
    Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """exabeam_raw=.*?({time}\d\d\/\d\d/\d{4} \d\d:\d\d:\d\d)""",
    """\WUser="({user_email}[^@]+@({email_domain}[^"]+))"""",
    """\WCmdlet="({activity}[^"]+)"""",
    """\WServer="({dest_host}[^"]+)"""",
    """\WParam="-Identity\s{0,100}'({resource}[^'"]+)""",
    """\WParam="-User\s{0,100}'({object}[^'"]+)""",
    """\WParam="-OwaMailboxPolicy\s{0,100}'({object}[^'"]+)""",
    """\WParam="-DomainController\s{0,100}'({object}[^'"]+)""",
    """\WParam="-AccessRights\s{0,100}'({object}[^'"]+)""",
    """\WParam="-Server\s{0,100}'({object}[^'"]+)""",
    """\WSuccess="({outcome}[^"]+)""""
  ]
}
```