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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """exabeam_raw=.*?({time}\d\d\/\d\d/\d{4} \d\d:\d\d:\d\d)""",
    """\WUser="({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """\WCmdlet="({activity}[^"]{1,2000})"""",
    """\WServer="({dest_host}[^"]{1,2000})"""",
    """\WParam="-Identity\s{0,100}'({resource}[^'"]{1,2000})""",
    """\WParam="-User\s{0,100}'({object}[^'"]{1,2000})""",
    """\WParam="-OwaMailboxPolicy\s{0,100}'({object}[^'"]{1,2000})""",
    """\WParam="-DomainController\s{0,100}'({object}[^'"]{1,2000})""",
    """\WParam="-AccessRights\s{0,100}'({object}[^'"]{1,2000})""",
    """\WParam="-Server\s{0,100}'({object}[^'"]{1,2000})""",
    """\WSuccess="({outcome}[^"]{1,2000})""""
  ]
}
```