#### Parser Content
```Java
{
Name = cef-snare-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Snare|""","""|Microsoft-Windows-Security-Auditing:4663|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}An attempt was made to access an object)""",
    """\sexternalId=({event_code}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\sdntdom=({domain}[^\s]{1,2000})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sduid=({logon_id}[^\s]{1,2000})""",
    """\scs1=({accesses}.+?)\s{1,100}\w+=""",
    """\sdvc=({host}[a-fA-F:\d.]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sfname=({file_path}.+?)\s{1,100}(?:$|\w+=)""",
    """\sfname=({file_parent}.+?)\\+(?:[^\\=]{1,2000}?)\s{1,100}(?:$|\w+=)""",
    """\sfname=[^=]{0,2000}\\({file_name}.*?({file_ext}\.[^\\:\s.]{1,2000})?)\s{1,100}(?:$|\w+=)""",
    """\scs3=({access_mask}\w+)"""
  ]
  DupFields = [ "host->dest_host" ]


}
```