import pygame
pygame.init()
class Testing:
    def __init__(self,text,x_coord,y_coord,window,type_of_font,size,color):
        self.text = text
        self.x_coord = x_coord
        self.y_coord = y_coord
        self.window = window
        self.type_of_font = type_of_font
        self.size = size
        self.color = color

    def object(self):
        font_render = pygame.font.Font(self.type_of_font,self.size)
        text_blit = font_render.render(self.text,True,self.color)
        self.text_blit = text_blit
    def blit(self):
        self.window.blit(self.text_blit,(self.x_coord,self.y_coord))
