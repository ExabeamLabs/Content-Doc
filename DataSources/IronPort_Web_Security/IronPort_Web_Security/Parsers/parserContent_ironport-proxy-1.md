#### Parser Content
```Java
{
Name = ironport-proxy-1
  TimeFormat = "dd/MM/yyyy:HH:mm:ss Z"
  Conditions = [ """IronPort-Web:""", """ TCP_""" ]
  Fields = ${IronPortParserTemplates.ironport-proxy.Fields} [
    """IronPort-Web:.+?({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d+)"\s\d+\s"({user_agent}[^"]+)""",
    """"IronPort-Web:.+"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]*"\s+$""",
    """"IronPort-Web:.+"[^"]*({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^"]*"\s+$""",
  ]
}
```