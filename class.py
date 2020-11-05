from tkinter import *

root = Tk()


class Register:
    def __init__(self, username, password, email_id, email_password):
        self.username = str(username)
        self.password = str(password)
        self.email_id = str(email_id)
        self.email_password = str(email_password)

    def check_pass_length(self):
        if self.password < 5 or self.email_password < 5:
            return False
        else:
            return True

    def saving(self):
        try:
            my_cursor.execute("select username from data_input")
            values_username = my_cursor.fetchall()
            for i in values_username:
                if self.username in i:
                    return False
        except:
            email_split = ""
            word = email_id_register.split()
            for i in word:
                for a in i:
                    if i == "@":
                        break
                    else:
                        email_split += i
            main_password = email_split + self.email_password
            static_salt_password = self.password + "@" + main_password
            cipher_text, salt_for_decryption = create_key(
                main_password, static_salt_password
            )
            my_cursor.execute(
                "insert into data_input values (%s, %s, %s, %s)",
                (self.username, self.email_id, cipher_text, salt_for_decryption),
            )

    def creation(self):
        for_hashing = self.password + self.username
        hash_pass = hashlib.sha512(for_hasing.encode()).hexdigest()
        file_name = self.username + ".bin"
        f = open(file_name, "wb")
        f.close()
        pyAesCrypt.encryptFile(
            file_name, file_name + ".bin.fenc", hash_pass, bufferSize
        )
        os.remove(file_name)
        windows = Tk()
        windows.withdraw()
        messagebox.showinfo("Success", "Your account has been created")
        windows.destroy()
        d = pygame.display.set_mode((800, 600))
        gameloop(d, self.username, self.password)
        pyAesCrypt.decryptFile(file_name + ".fenc", file_name, hash_pass, bufferSize)
