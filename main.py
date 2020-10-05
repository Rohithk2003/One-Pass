import pygame
import math
pygame.init()
clock = pygame.time.Clock()
# for display
win = pygame.display.set_mode((800, 600))
idle = [pygame.image.load('idle0.png'), pygame.image.load('idle1.png'), pygame.image.load('idle2.png'), pygame.image.load(
    'idle3.png'), pygame.image.load('idle0.png'), pygame.image.load('idle1.png'), pygame.image.load('idle2.png'), pygame.image.load('idle3.png')]
low = [pygame.image.load('slide0.png'), pygame.image.load('slide1.png'), pygame.image.load(
    'slide0.png'), pygame.image.load('slide1.png'), pygame.image.load('slide0.png'), pygame.image.load('slide1.png')]
run = [pygame.image.load('run1.png'), pygame.image.load('run2.png'), pygame.image.load(
    'run3.png'), pygame.image.load('run4.png'), pygame.image.load('run5.png'), pygame.image.load('run5.png')]
back = pygame.image.load('background.png')
jump = [pygame.image.load('jump0.png'), pygame.image.load('jump3.png'), pygame.image.load(
    'jump10.png'), pygame.image.load('jump11.png'), pygame.image.load('jump12.png'), pygame.image.load('jump13.png')]


class player(object):
    def __init__(self, player_x, player_y):
        self.x = player_x
        self.y = player_y
        self.running = False
        self.low1 = False
        self.isjump = False
        self.jumpcount = 10
        self.walkcount = 0

    def draw(self, win):
        if self.walkcount + 1 >= 18:
            self.walkcount = 0

        if self.running:
            self.walkcount += 1
            win.blit(run[self.walkcount // 3], (self.x, self.y))
        elif self.low1:
            win.blit(low[self.walkcount // 3], (self.x, self.y))
            self.walkcount += 1
        else:
            win.blit(idle[int(self.walkcount // 3)], (self.x, self.y))


# color
black = (0, 0, 0)
white = (255, 255, 255)
red = (255, 0, 0)
blue = (0, 255, 0)
green = (0, 0, 255)

# for the movement and display of the game and display player images as sprite

man = player(100, 500)


def redraw():

    win.blit(back, (0, 0))
    man.draw(win)
    pygame.display.update()


def gameloop():
    while True:
        clock.tick(60)
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                pygame.quit()
                quit()

        keys = pygame.key.get_pressed()
        man.x += 10
        man.running = True
        if keys[pygame.K_c]:
            man.x += 10
            man.low1 = True
            man.running = False
        else:
            man.running = False
            man.low1 = False
            man.walkcount = 0
        if not(man.isjump):
            if keys[pygame.K_SPACE]:
                man.isjump = True
        else:
            if man.jumpcount >= -10:
                if man.jumpcount < 0:
                    var = -1
                else:
                    var = 1
                man.y -= (man.jumpcount**2) * 0.2 * var
                man.jumpcount -= 1

            else:
                man.isjump = False
                man.jumpcount = 10
        redraw()


gameloop()
