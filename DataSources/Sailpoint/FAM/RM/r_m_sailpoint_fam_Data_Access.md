Vendor: Sailpoint
=================
### Product: [FAM](../ds_sailpoint_fam.md)
### Use-Case: [Data Access](../../../../UseCases/uc_data_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  31   |   17   |     1      |      4      |    4    |

| Event Type  | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-delete | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-UA-UI-F</b>: First file activity from ISP<br> ↳ <b>FA-UA-UC-F</b>: First file activity from country for user<br> ↳ <b>FA-UA-UC-A</b>: Abnormal file activity from country for user<br> ↳ <b>FA-UA-GC-F</b>: First file activity from country for group<br> ↳ <b>FA-UA-GC-A</b>: Abnormal file activity from country for group<br> ↳ <b>FA-UA-OC-F</b>: First file activity from country for organization<br> ↳ <b>FA-UA-OC-A</b>: Abnormal file activity from country for organization<br> ↳ <b>FA-UTi</b>: Abnormal user file activity time<br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-FG-A</b>: Abnormal access to folder for group<br> ↳ <b>FA-FU-F</b>: First access to folder by user<br> ↳ <b>FA-FU-A</b>: Abnormal access to folder by user<br> ↳ <b>FA-UH-F</b>: First file access from asset for user<br> ↳ <b>FA-UH-A</b>: Abnormal file access from asset for user<br> ↳ <b>FA-OZ-F</b>: First file access from network zone for organization<br> ↳ <b>FA-OZ-A</b>: Abnormal file access from network zone for organization<br> ↳ <b>FA-UZ-F</b>: First file access from network zone for user<br> ↳ <b>FA-UZ-A</b>: Abnormal file access from network zone for user<br> ↳ <b>FA-UA-F</b>: First file access activity for user<br> ↳ <b>FA-UA-A</b>: Abnormal file access activity for user<br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br> ↳ <b>FA-OU-F</b>: First access to source code files for user in the organization<br> ↳ <b>FA-OU-A</b>: Abnormal access to source code files for user in the organization<br> ↳ <b>FA-OG-F</b>: First access to source code files for user in the peer group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user<br> ↳ <b>FA-SFU-A</b>: Abnormal access to folder containing source code by user<br> ↳ <b>FA-UD-F</b>: First file server access for user<br> ↳ <b>FA-UD-A</b>: Abnormal file server access for user<br> ↳ <b>FA-GD-F</b>: First file server access for group<br> ↳ <b>FA-GD-A</b>: Abnormal file server access for group |  • <b>FA-GD</b>: File server access per group<br> • <b>FA-UD</b>: File server access per user<br> • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-OU</b>: Users accessing source code files in the organization<br> • <b>FA-FT-EXEC</b>: Executive Folders<br> • <b>FA-UA</b>: File access activities for user<br> • <b>FA-UZ</b>: File accesses from network zone for user<br> • <b>FA-OZ</b>: File accesses from network zone for organization<br> • <b>FA-UH</b>: User file access source host<br> • <b>FA-FU</b>: Folder access by users<br> • <b>FA-FG</b>: Folder access by groups<br> • <b>FA-UTi</b>: File activity time for user<br> • <b>FA-UA-OC</b>: Countries for organization file activities<br> • <b>FA-UA-GC</b>: Countries for peer groups file activities<br> • <b>FA-UA-UC</b>: Countries for user file activity<br> • <b>FA-UA-UI-new</b>: ISP of users during file activity |
| file-read   | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-UA-UI-F</b>: First file activity from ISP<br> ↳ <b>FA-UA-UC-F</b>: First file activity from country for user<br> ↳ <b>FA-UA-UC-A</b>: Abnormal file activity from country for user<br> ↳ <b>FA-UA-GC-F</b>: First file activity from country for group<br> ↳ <b>FA-UA-GC-A</b>: Abnormal file activity from country for group<br> ↳ <b>FA-UA-OC-F</b>: First file activity from country for organization<br> ↳ <b>FA-UA-OC-A</b>: Abnormal file activity from country for organization<br> ↳ <b>FA-UTi</b>: Abnormal user file activity time<br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-FG-A</b>: Abnormal access to folder for group<br> ↳ <b>FA-FU-F</b>: First access to folder by user<br> ↳ <b>FA-FU-A</b>: Abnormal access to folder by user<br> ↳ <b>FA-UH-F</b>: First file access from asset for user<br> ↳ <b>FA-UH-A</b>: Abnormal file access from asset for user<br> ↳ <b>FA-OZ-F</b>: First file access from network zone for organization<br> ↳ <b>FA-OZ-A</b>: Abnormal file access from network zone for organization<br> ↳ <b>FA-UZ-F</b>: First file access from network zone for user<br> ↳ <b>FA-UZ-A</b>: Abnormal file access from network zone for user<br> ↳ <b>FA-UA-F</b>: First file access activity for user<br> ↳ <b>FA-UA-A</b>: Abnormal file access activity for user<br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br> ↳ <b>FA-OU-F</b>: First access to source code files for user in the organization<br> ↳ <b>FA-OU-A</b>: Abnormal access to source code files for user in the organization<br> ↳ <b>FA-OG-F</b>: First access to source code files for user in the peer group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user<br> ↳ <b>FA-SFU-A</b>: Abnormal access to folder containing source code by user<br> ↳ <b>FA-UD-F</b>: First file server access for user<br> ↳ <b>FA-UD-A</b>: Abnormal file server access for user<br> ↳ <b>FA-GD-F</b>: First file server access for group<br> ↳ <b>FA-GD-A</b>: Abnormal file server access for group |  • <b>FA-GD</b>: File server access per group<br> • <b>FA-UD</b>: File server access per user<br> • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-OU</b>: Users accessing source code files in the organization<br> • <b>FA-FT-EXEC</b>: Executive Folders<br> • <b>FA-UA</b>: File access activities for user<br> • <b>FA-UZ</b>: File accesses from network zone for user<br> • <b>FA-OZ</b>: File accesses from network zone for organization<br> • <b>FA-UH</b>: User file access source host<br> • <b>FA-FU</b>: Folder access by users<br> • <b>FA-FG</b>: Folder access by groups<br> • <b>FA-UTi</b>: File activity time for user<br> • <b>FA-UA-OC</b>: Countries for organization file activities<br> • <b>FA-UA-GC</b>: Countries for peer groups file activities<br> • <b>FA-UA-UC</b>: Countries for user file activity<br> • <b>FA-UA-UI-new</b>: ISP of users during file activity |
| file-write  | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-UA-UI-F</b>: First file activity from ISP<br> ↳ <b>FA-UA-UC-F</b>: First file activity from country for user<br> ↳ <b>FA-UA-UC-A</b>: Abnormal file activity from country for user<br> ↳ <b>FA-UA-GC-F</b>: First file activity from country for group<br> ↳ <b>FA-UA-GC-A</b>: Abnormal file activity from country for group<br> ↳ <b>FA-UA-OC-F</b>: First file activity from country for organization<br> ↳ <b>FA-UA-OC-A</b>: Abnormal file activity from country for organization<br> ↳ <b>FA-UTi</b>: Abnormal user file activity time<br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-FG-A</b>: Abnormal access to folder for group<br> ↳ <b>FA-FU-F</b>: First access to folder by user<br> ↳ <b>FA-FU-A</b>: Abnormal access to folder by user<br> ↳ <b>FA-UH-F</b>: First file access from asset for user<br> ↳ <b>FA-UH-A</b>: Abnormal file access from asset for user<br> ↳ <b>FA-OZ-F</b>: First file access from network zone for organization<br> ↳ <b>FA-OZ-A</b>: Abnormal file access from network zone for organization<br> ↳ <b>FA-UZ-F</b>: First file access from network zone for user<br> ↳ <b>FA-UZ-A</b>: Abnormal file access from network zone for user<br> ↳ <b>FA-UA-F</b>: First file access activity for user<br> ↳ <b>FA-UA-A</b>: Abnormal file access activity for user<br> ↳ <b>FA-FT-EXEC</b>: Non-Executive user accessed executive folder<br> ↳ <b>FA-OU-F</b>: First access to source code files for user in the organization<br> ↳ <b>FA-OU-A</b>: Abnormal access to source code files for user in the organization<br> ↳ <b>FA-OG-F</b>: First access to source code files for user in the peer group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user<br> ↳ <b>FA-SFU-A</b>: Abnormal access to folder containing source code by user<br> ↳ <b>FA-UD-F</b>: First file server access for user<br> ↳ <b>FA-UD-A</b>: Abnormal file server access for user<br> ↳ <b>FA-GD-F</b>: First file server access for group<br> ↳ <b>FA-GD-A</b>: Abnormal file server access for group |  • <b>FA-GD</b>: File server access per group<br> • <b>FA-UD</b>: File server access per user<br> • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-OU</b>: Users accessing source code files in the organization<br> • <b>FA-FT-EXEC</b>: Executive Folders<br> • <b>FA-UA</b>: File access activities for user<br> • <b>FA-UZ</b>: File accesses from network zone for user<br> • <b>FA-OZ</b>: File accesses from network zone for organization<br> • <b>FA-UH</b>: User file access source host<br> • <b>FA-FU</b>: Folder access by users<br> • <b>FA-FG</b>: Folder access by groups<br> • <b>FA-UTi</b>: File activity time for user<br> • <b>FA-UA-OC</b>: Countries for organization file activities<br> • <b>FA-UA-GC</b>: Countries for peer groups file activities<br> • <b>FA-UA-UC</b>: Countries for user file activity<br> • <b>FA-UA-UI-new</b>: ISP of users during file activity |