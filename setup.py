import cx_Freeze

executables = [cx_Freeze.Executable("a.py")]

cx_Freeze.setup(
    name="Jet Fighter",
    options={"build_exe": {"packages":["tkinter","smtplib","glob","pyAesCrypt","mysql.connector","atexit","tkinter.ttk","cryptography","geopy","geocoder","socket","hashlib","base64","passlib","pymsgbox","pygame"],
                           "include_files":["facebook.png","github.png","instagram.png","google.png"]}},
    executables = executables

    )
