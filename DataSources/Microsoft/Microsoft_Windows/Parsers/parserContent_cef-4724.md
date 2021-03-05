#### Parser Content
```Java
{
Name = cef-4724
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-password-reset"
    TimeFormat = "epoch"
    Conditions = [ "externalId=4724 ", """An attempt was made to reset an account's password."""]
    Fields = [ """\sdhost=({host}[^\s]+)""",
      """({event_name}An attempt was made to reset an account's password)""",
        """Microsoft-Windows-Security-Auditing:({event_code}\d{4})""",
        """\srt=({time}\d+)""",
        """\ssntdom=({domain}[^\s]+)""",
        """\ssuser=({user}.+?)\s+\w+=""",
        """\sduser=({target_user}.+?)\s+\w+=""",
        """\ssuid=({logon_sid}[^\s]+)"""
        """Security_,ID=({user_sid}[^\s]+?)(\s|\||$)""",
        """\sdntdom=({target_domain}.+?)\s+\w+=""",
    ]
    DupFields = [ "host->dest_host" ]
    
}
```