#### Parser Content
```Java
{
Name = u-okta-failed-app-login
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Sumo
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """|OKTA|OKTA Identity Provider|""","""|Sign-in Failure|"""]
    Fields = [
  """start=({time}\d\d\d\d\-\d+\-\d+T\d+:\d+:\d+:\d+)""",
        """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """instance=({host}[^,]+)""",
        """user:\s({user}[^,]+)""",
        """msg=Sign-In Failed - ({failure_reason}[^:,]+)""",
        """cs3=({user_agent}.+?), \w+=""",
        """cs3=(?:-|({browser}[\w\-]+))""",
        """cs3=(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
        """cs3=(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
        """cs3=(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
        """cs3=(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
        """({app}Okta)"""
    ]
}
```