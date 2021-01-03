

class Deletion:
    def __init__(self, real_username, hashed_password, window, object):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.window = window
        self.object = object

    def delete_social_media_account(self, password_button, Value, *account_name):

        if Value:
            delete_med_account = Tk()
            delete_med_account.config(bg="#292A2D")
            delete_med_account.title("Delete Account")
            selectaccount = Combobox(
                delete_med_account, width=27, state="#292A2D"
            )
            # Adding combobox drop down list
            tu = ()
            with open(f"{self.real_username}decrypted.bin", "rb") as selectfile:
                try:
                    ac = pickle.load(selectfile)
                    for i in ac:
                        tu += (i[2],)
                except:
                    pass
            delete = Button(
                delete_med_account,
                text="Delete",
                fg="white",
                bg="#292A2D",
                command=lambda: self.change_account_name(
                    str(selectaccount.get()), password_button, True
                ),
            )
            selectaccount["values"] = tu
            change_account_label = Label(
                delete_med_account,
                fg="white",
                bg="#292A2D",
                text="Select account to be deleted",
            )
            selectaccount.grid(column=1, row=0)
            change_account_label.grid(column=0, row=0)
            selectaccount.current()
            delete.grid(row=1, column=1)

        else:
            a = Tk()
            a.overrideredirect(1)
            a.withdraw()
            result = messagebox.askyesno(
                "Delete Account", "Are you sure you want to delete you account?"
            )
            a.destroy()
            if result:

                self.change_account_name(
                    account_name[0], password_button, False)
            else:
                pass

    def change_account_name(self, account_name, button, val):
        if val:
            result = messagebox.askyesno(
                "Confirm", "Are you sure that you want to delete your account"
            )
        else:
            result = True
        if result == True:
            with open(f"{self.real_username}decrypted.bin", "rb") as f:
                values = pickle.load(f)
                for i in values:
                    if i[2] == account_name:
                        inde = values.index(i)
                        values.pop(inde)

                f.close()
            try:
                os.remove(f"{self.real_username}.bin.fenc")
            except:
                pass
            with open(f"{self.real_username}decrypted.bin", "wb") as f:
                pickle.dump(values, f)
                f.close()

            pyAesCrypt.encryptFile(
                f"{self.real_username}decrypted.bin",
                f"{self.real_username}.bin.fenc",
                self.hashed_password,
                bufferSize,
            )
            a = Tk()
            a.withdraw()
            messagebox.showinfo(
                "Success", f"{account_name}  has been  deleted")
            a.destroy()

            # getting whether the password button is pressed or not
            state_current = button["state"]
            if state_current == DISABLED:
                gameloop(self.real_username, self.hashed_password,
                         self.window, button, self.object)
            else:
                pass
        else:
            a = Tk()
            a.withdraw()
            messagebox.showinfo("Error", "Please try again")
            a.destroy()

    def delete_main_account(self, window, *another_window):
        answer = messagebox.askyesno(
            "Delete Account", "Are you sure you want to delete you account"
        )
        if answer:
            result = simpledialog.askstring(
                "Delete Account",
                f"Please type {self.real_username}-CONFIRM to delete your account",
            )
            if result == f"{self.real_username}-CONFIRM":
                try:
                    os.remove(self.real_username + "decrypted.bin")
                    os.remove(self.real_username + ".bin.fenc")

                    self.object.execute(
                        "delete from data_input where username = (?)",
                        (simple_encrypt(self.real_username),),
                    )
                    messagebox.showinfo(
                        "Account deletion",
                        "Success your account has been deleted. See you!!",
                    )
                    window.destroy()
                    for i in another_window:
                        i.destroy()
                    if not os.path.exists(f"{self.real_username}.bin.fenc"):
                        quit()
                except:
                    pass
            else:
                messagebox.showwarning("Error", "Please try again")
        else:
            pass
