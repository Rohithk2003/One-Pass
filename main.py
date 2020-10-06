import pygame
from pygame.locals import *
import os
import sys
import math
import time

pygame.init()
clock = pygame.time.Clock()
# for display
win = pygame.display.set_mode((1400, 447))
idle = [pygame.image.load(os.path.join(
    'data', 'idle' + str(x)+'.png')) for x in range(0, 10)]
low = [pygame.image.load(os.path.join(
    'data', 'slide' + str(x)+'.png')) for x in range(0, 10)]
run = [pygame.image.load(os.path.join('data', 'run' + str(x)+'.png'))
       for x in range(0, 10)]
back = pygame.image.load('bg.png')
jump = [pygame.image.load(os.path.join(
    'data', 'jump' + str(x)+'.png')) for x in range(0, 10)]
fight = [pygame.image.load(os.path.join(
    'data', 'attack' + str(x)+'.png')) for x in range(0, 10)]

bgX = 0
bgX2 = back.get_width()


class player(object):
    def __init__(self, player_x, player_y):
        self.x = player_x
        self.y = player_y
        self.running = False
        self.low1 = False
        self.isjump = False
        self.jumpcount = 10
        self.walkcount = 0
        self.idle1 = False
        self.fighting = False
        self.testing_count = 0

    def draw(self, win):
        if self.walkcount + 1 >= 27:
            self.walkcount = 0
        if self.running:
            self.walkcount += 1
            win.blit(run[self.walkcount // 3], (self.x, self.y))
        elif self.low1:
            win.blit(low[self.walkcount // 3], (self.x, self.y))
            self.walkcount += 1

        elif self.idle1:
            win.blit(idle[int(self.walkcount // 3)], (self.x, self.y))

    def testing(self, win):
        if self.testing_count > 27:
            self.testing_count = 0
        if self.fighting:
            win.blit(fight[(self.testing_count // 3)], (self.x, self.y))
            self.testing_count += 1


# color
black = (0, 0, 0)
white = (255, 255, 255)
red = (255, 0, 0)
blue = (0, 255, 0)
green = (0, 0, 255)

# for the movement and display of the game and display player images as sprite

man = player(100, 320)


def redraw():

    win.blit(back, (bgX, 0))
    win.blit(back, (bgX2, 0))

    man.draw(win)
    man.testing(win)
    pygame.display.update()


pygame.time.set_timer(USEREVENT + 1, 500)  # Sets the timer for 0.5 seconds
fps = 27


def gameloop():
    global fps
    global bgX
    global bgX2
    a = False
    while True:
        redraw()
        if a:
            bgX -= 2
            bgX2 -= 2
        if bgX < back.get_width() * -1:  # If our bg is at the -width then reset its position
            bgX = back.get_width()

        if bgX2 < back.get_width() * -1:
            bgX2 = back.get_width()
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                pygame.quit()
                quit()
            if e.type == USEREVENT + 1:
                fps += 1

        keys = pygame.key.get_pressed()
        man.running = True
        if keys[pygame.K_RIGHT]:
            man.x += 0.1
            a = True
            man.low1 = False
            man.fighting = False
            man.idle1 = False

            if keys[pygame.K_c]:
                man.x += 0.1
                man.low1 = True
                man.running = False
                man.fighting = False
                man.idle1 = False

        elif keys[pygame.K_c]:
            man.x += 0.1
            a = False
            man.low1 = True
            man.running = False
            man.fighting = False
            man.idle1 = False
        elif keys[pygame.K_p]:
            man.fighting = True
            man.low1 = False
            man.running = False
            man.idle1 = False
        else:
            a = False
            man.fighting = False
            man.idle1 = True
            man.running = False
            man.low1 = False

            man.walkcount = 0
        if not(man.isjump) and man.low1 == False:
            if keys[pygame.K_SPACE]:
                man.isjump = True
        elif man.isjump == True and man.low1 == False:
            if man.jumpcount >= -10:
                if man.jumpcount < 0:
                    var = -1
                else:
                    var = 1
                man.y -= ((man.jumpcount**2) / 5) * var
                man.jumpcount -= 0.5

            else:
                man.isjump = False
                man.jumpcount = 10
        clock.tick(fps)


gameloop()
