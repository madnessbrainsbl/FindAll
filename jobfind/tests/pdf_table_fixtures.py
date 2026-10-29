from PIL import Image, ImageDraw, ImageFont


def scanned_tables(path):
    font = ImageFont.truetype('arial.ttf', 38)
    pages = []
    matrices = [
        [['Регион', '2024', '2025'], ['Север', '1200', '3400'], ['Юг', '5600', ''], ['Запад', '7800', '9100']],
        [['Quarterly report']*3, ['Region', 'Units', 'Revenue'], ['North', '12', '42000'],
         ['North', '18', '57000'], ['South', '24', '63000']],
        [['Region', 'Units', 'Revenue'], ['North', '12', '42000'], ['South', '18', '57000'],
         ['West', '24', '63000'], ['East', '36', '84000']],
    ]
    for page_number, matrix in enumerate(matrices):
        image = Image.new('RGB', (1600, 1300), 'white')
        draw = ImageDraw.Draw(image)
        draw.text((180, 110), 'SYNTHETIC TABLE RESEARCH', font=font, fill='black')
        for r, row in enumerate(matrix):
            for c, value in enumerate(row):
                if page_number == 1 and ((r == 0 and c > 0) or (r == 3 and c == 0)):
                    continue
                colspan = 3 if page_number == 1 and r == 0 else 1
                rowspan = 2 if page_number == 1 and r == 2 and c == 0 else 1
                x, y = 180 + c*390, 280 + r*(80 if page_number == 2 else 150)
                if page_number != 2:
                    draw.rectangle((x, y, x+390*colspan, y+150*rowspan), outline='black', width=4)
                draw.text((x+25, y+45), value, font=font, fill='black')
        pages.append(image)
    pages[0].save(path, 'PDF', resolution=150, save_all=True, append_images=pages[1:])
    for image in pages:
        image.close()
    return matrices
