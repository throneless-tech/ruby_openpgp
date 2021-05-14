require 'open3'

class TypesGenerator
  @@types = [
    'PGP_STATUS',
    'PGP_ARMOR_KIND',
    'PGP_REVOCATION_STATUS',
    'PGP_REASON_FOR_REVOCATION',
    'PGP_PUBLIC_KEY_ALGO',
    'PGP_TAG',
    'PGP_CERT_CIPHER',
    'PGP_MESSAGE_LAYER',
    'PGP_VERIFICATION_RESULT'
  ]

  def self.generate(cflags, c_file, rb_file)
    parsed_types = get_all_types(cflags).split

    File.open(c_file, 'w') do |out|
      generate_preamble(out, rb_file)

      @@types.each do |type|
        generate_type_comment(out, type)
        parse_enum_variants(parsed_types, type).each do |v|
          generate_enum_constant(out, v)
        end
      end

      generate_closing(out)
    end
  end

  private

  def self.get_all_types(cflags)
    tmp_file = 'tmp_header_file.h'
    File.open(tmp_file, 'w') do |file|
      file.write("#include <sequoia/openpgp.h>\n")
    end
    types, err = Open3.capture2("gcc", "-E", cflags.strip, tmp_file)

    File.delete(tmp_file) if File.exists?(tmp_file)

    unless err.success?
      raise StandardError.new('Cannot create sequoia types with preprocessor')
    end

    types
  end

  def self.parse_enum_variants(types, type)
    variants = []
    r = Regexp.new('(' + type + '[A-Z0-9_]+)\s*')
    types.each do |line|
      if match = r.match(line)
        variants << match[1]
      end
    end
    variants
  end

  def self.generate_preamble(out, file_name)
    out.write("#include <stdio.h>\n")
    out.write("#include \"sequoia/openpgp.h\"\n\n")
    out.write("int main (int argc, char **argv) {\n")
    out.write("  FILE *f = fopen(\"" + file_name + "\", \"w\");\n")
    out.write('  fprintf(f, "# THIS IS A GENERATED FILE. PLEASE DONT CHANGE IT MANUALLY\n");' + "\n")
  end

  def self.generate_type_comment(out, type)
    out.write('  fprintf(f, "\n# variants for ' + type + '\n");' + "\n")
  end

  def self.generate_enum_constant(out, name)
    out.write('  fprintf(f, "' + name + ' = %d\n", ' + name + ");\n")
  end

  def self.generate_closing(out)
    out.write("  fclose(f);\n")
    out.write("  return 0;\n")
    out.write("}\n")
  end
end
