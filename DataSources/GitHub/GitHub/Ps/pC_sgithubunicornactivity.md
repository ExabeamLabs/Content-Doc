#### Parser Content
```Java
{
Name = s-github-unicorn-activity
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "github_unicorn", """ controller=""" ]
  Fields = [
    """\snow="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({host}\S+)\s{1,100}github_unicorn:""",
    """\scurrent_user=(?:nil|({user}[^\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\suser=(?:nil|({user}[^\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\srepo=(?:nil|({object}[^\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\saction=({activity}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\sremote_address=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\srequest_host=(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\suser_agent="({user_agent}[^"]{1,2000})"""",
    """\suser_agent=({user_agent}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\suser_agent="(?:-|({browser}[\w\-]{1,2000}))""",
    """\suser_agent="(?:-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
    """\suser_agent="(?:-|({browser}[^\/]{1,2000}).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """\suser_agent="(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\suser_agent="(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
    """\sstatus=({result}\d{1,100})""",
    """({app}github)""",
    """accept=({mime}[^\s]{1,2000})"""
  ]


}
```