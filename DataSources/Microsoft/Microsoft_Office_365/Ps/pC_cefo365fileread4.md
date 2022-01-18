#### Parser Content
```Java
{
Name = cef-o365-file-read-4
  Conditions = [ """|Microsoft|""", """|FileDownloaded|""", """eventId=""" ]

cef-o365-file-read = {
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wact=({accesses}.+?)\s{0,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\Wcs5=({app}.+?)\s{0,100}(\w+=|$)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wduser=({user_email}[^@\s]{1,2000}@[^\s@]{1,2000})""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@[^\s@]{1,2000})""",
    """\Wsuid=(?!\S+@\S+)({user}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wsuid=({user_email}[^\s@]{1,2000}@[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\WfilePath=({file_path}.+?)\s{0,100}(\w+=|$)""",
    """\WfilePath=(({file_parent}.+?)\/({file_name}[^\/]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\WfilePath=.*?(\.({file_ext}[^\/\.]{0,2000}?))?\s{0,100}(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s{0,100}(\w+=|$)""",
    """\WrequestClientApplication=({user_agent}.+?)\s{0,100}(\w+=|$)""",
  
}
```