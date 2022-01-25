#### Parser Content
```Java
{
Name = cef-o365-app-activity-4
  Conditions = [ """|Microsoft|""", """|CompanyLinkCreated|""", """eventId=""" ]

cef-o365-app-activity = {
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wact=({activity}.+?)\s{0,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){2}({app}[^\|]{1,2000})""",
    """\Wcs5=({app}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({user_email}[^@\s]{1,2000}@[^\s@]{1,2000})""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@[^\s@]{1,2000})""",
    """\Wsuid=(?!\S+@\S+)({user}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wsuid=({user_email}[^\s@]{1,2000}@[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wsuid=.*?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{0,100}""",
    """\Wduid=({object}.+?)\s{0,100}(\w+=|$)""",
    """(\|SharingSet\||\|WACTokenShared\||\|VideoRequested\|).+?filePath=({object}.+?)\s{0,100}(\w+=|$)""",
    """(\|SearchQueryPerformed\||\|SearchResultReturned\|).+?fileType=({object}.+?)\s{0,100}(\w+=|$)""",
    """\WfilePath=({resource}.+?)\s{0,100}(\w+=|$)""",
    """\W(categoryOutcome|outcome)=\/?({outcome}.+?)\s{0,100}(\w+=|$)""",
    """\WrequestClientApplication=({user_agent}.+?)\s{0,100}(\w+=|$)""",
    """\WrequestClientApplication=(?:-|Mozilla\/.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  
}
```