import os
import os.path as path


def get_binary_image(img_path):
    if path.exists(img_path):
        with open(img_path, 'rb') as file:
            return file.read()
    raise ValueError('Image path "%s" doesn\'t exist' % img_path)


def get_images_list(directory):
    if path.exists(directory):
        content = [directory + '\\' + x for x in filter(_is_image_file, os.listdir(directory))]
        return list(map(path.abspath, content))
    raise ValueError('Directory "%s" doesn\'t exist' % directory)


def _is_image_file(file):
    return file[-4:] in ('.jpg', '.png', '.bmp', 'gif')
