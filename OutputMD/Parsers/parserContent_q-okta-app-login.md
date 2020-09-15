#### Parser Content
```Java
{
Name = q-okta-app-login
    Vendor = Okta
    Product = Okta MFA
    Lms = QRadar
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"Sign-in successful,""", """,published"""", """,action"""" ]
    Fields=[
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wpublished"\s*:\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\WipAddress"\s*:\s*"({src_ip}[\da-fA-F\.:]+)""",
    """\Wmessage"\s*:\s*"({outcome}[^",]+)""",
    """"targets"\s*:\s*\[\{[^\]]*?\WdisplayName"\s*:\s*"({user_fullname}[^",]+)""",
    """"targets"\s*:\s*\[\{[^\}]*?\Wlogin"\s*:\s*"({user_email}[^",]+)""",
    """({app}Okta)""",
    """"actors":\[[^\]]*?"id":"({user_agent}[^"]+?),displayName[^\}]*?objectType":"Client"""",
    """"actors":\[[^\]]*?objectType":"Client"[^\}]*?"id":"({user_agent}[^"]+?),displayName""",
    """"actors":\[[^\]]*?,displayName":"({browser}[^",]+)[^\}]*?objectType":"Client"""",
    """"actors":\[[^\]]*?objectType":"Client"[^\}]*?,displayName":"({browser}[^",]+)""",
    #""""actors":\[.*?\{("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s*:\s*"Client",?("?[^"]+"\s*:\s*([^"\\]|(\\\\)*\\"|\\)+",?)*"?id"\s*:\s*"({user_agent}[^"]+)"?,("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*\}\]""",
    #""""actors":\[.*?\{("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?id"\s*:\s*"({user_agent}[^"]+)"?,("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s*:\s*"Client",?("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+",?)*\}\]""",
    #""""actors":\[.*?\{("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s*:\s*"Client",?("?[^"]+"\s*:\s*([^"\\]|(\\\\)*\\"|\\)+",?)*"?displayName"\s*:\s*"({browser}[^"]+)"?,("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*\}\]""",
    #""""actors":\[.*?\{("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?displayName"\s*:\s*"({browser}[^"]+)"?,("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s*:\s*"Client",?("?[^"]+"\s*:\s*"([^"\\]|(\\\\)*\\"|\\)+"?,?)*\}\]""",
    """"id"\s*:\s*"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```