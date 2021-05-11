#### Parser Content
```Java
{
Name = q-okta-app-login
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = QRadar
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"Sign-in successful,""", """,published"""", """,action"""" ]
    Fields=[
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\Wpublished"\s{0,100}:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\WipAddress"\s{0,100}:\s{0,100}"({src_ip}[\da-fA-F\.:]+)""",
    """\Wmessage"\s{0,100}:\s{0,100}"({outcome}[^",]+)""",
    """"targets"\s{0,100}:\s{0,100}\[\{[^\]]*?\WdisplayName"\s{0,100}:\s{0,100}"({user_fullname}[^",]+)""",
    """"targets"\s{0,100}:\s{0,100}\[\{[^\}]*?\Wlogin"\s{0,100}:\s{0,100}"({user_email}[^",]+)""",
    """({app}Okta)""",
    """"actors":\[[^\]]*?"id":"({user_agent}[^"]+?),displayName[^\}]*?objectType":"Client"""",
    """"actors":\[[^\]]*?objectType":"Client"[^\}]*?"id":"({user_agent}[^"]+?),displayName""",
    """"actors":\[[^\]]*?,displayName":"({browser}[^",]+)[^\}]*?objectType":"Client"""",
    """"actors":\[[^\]]*?objectType":"Client"[^\}]*?,displayName":"({browser}[^",]+)""",
    #""""actors":\[.*?\{("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s{0,100}:\s{0,100}"Client",?("?[^"]+"\s{0,100}:\s{0,100}([^"\\]|(\\\\)*\\"|\\)+",?)*"?id"\s{0,100}:\s{0,100}"({user_agent}[^"]+)"?,("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*\}\]""",
    #""""actors":\[.*?\{("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?id"\s{0,100}:\s{0,100}"({user_agent}[^"]+)"?,("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s{0,100}:\s{0,100}"Client",?("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+",?)*\}\]""",
    #""""actors":\[.*?\{("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s{0,100}:\s{0,100}"Client",?("?[^"]+"\s{0,100}:\s{0,100}([^"\\]|(\\\\)*\\"|\\)+",?)*"?displayName"\s{0,100}:\s{0,100}"({browser}[^"]+)"?,("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*\}\]""",
    #""""actors":\[.*?\{("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?displayName"\s{0,100}:\s{0,100}"({browser}[^"]+)"?,("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*"?objectType"\s{0,100}:\s{0,100}"Client",?("?[^"]+"\s{0,100}:\s{0,100}"([^"\\]|(\\\\)*\\"|\\)+"?,?)*\}\]""",
    """"id"\s{0,100}:\s{0,100}"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```