import pygame
pygame.init()
# for display
win = pygame.display.set_mode((800, 600))
idle = pygame.image.load('idle.png')
jump = pygame.image.load('jump.png')
low = [pygame.image.load('low1.png'), pygame.image.load('low2.png')]
run = [pygame.image.load('run1.png'), pygame.image.load('run2.png')]
back = pygame.image.load('back.png')
running = False
jumping = False
low1 = False
x = 50
y = 425
walkcount = 0
# color
black = (0, 0, 0)
white = (255, 255, 255)
red = (255, 0, 0)
blue = (0,255,0)

# for the movement and display of the game and display player images as sprite


def redraw():
    global walkcount
    win.fill((0, 0, 0))
    if walkcount + 1 >= 6:
        walkcount = 0
    if running:
        win.blit(run[walkcount // 3], (x, y))
        walkcount += 1
    elif low1:
        win.blit(low[walkcount // 3], (x, y))
    else:
        win.blit(idle, (x, y))

    pygame.display.update()


while True:

    for e in pygame.event.get():
        if e.type == pygame.QUIT:
            pygame.quit()
            quit()
    keys = pygame.key.get_pressed()
    if keys[pygame.K_RIGHT]:
        x += 0.5
        running = True
        jumping = False
        low1 = False
    elif keys[pygame.K_SPACE]:
        jumping = True
        running = False
        low1 = False
    elif keys[pygame.K_e]:
        low1 = True
        jumping = False
        running = False
    else:
        running = False
        jumping = False
        low1 = False
        walkcount = 0
    redraw()
