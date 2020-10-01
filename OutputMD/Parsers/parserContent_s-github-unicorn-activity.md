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
    """({host}\S+)\s+github_unicorn:""",
    """\scurrent_user=(?:nil|({user}[^\s]+))\s+(\w+=|$)""",
    """\suser=(?:nil|({user}[^\s]+))\s+(\w+=|$)""",
    """\srepo=(?:nil|({object}[^\s]+))\s+(\w+=|$)""",
    """\saction=({activity}[^\s]+)\s+(\w+=|$)""",
    """\sremote_address=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\srequest_host=(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))\s+(\w+=|$)""",
    """\suser_agent="({user_agent}[^"]+)"""",
    """\suser_agent=({user_agent}[^\s]+)\s+(\w+=|$)""",
    """\suser_agent="(?:-|({browser}[\w\-]+))""",
    """\suser_agent="(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
    """\suser_agent="(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """\suser_agent="(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\suser_agent="(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
    """\sstatus=({result}\d+)""",
    """({app}github)""",
    """accept=({mime}[^\s]+)"""
  ]
}
```