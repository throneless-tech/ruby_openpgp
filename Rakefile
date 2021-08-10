# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

require "rubocop/rake_task"

RuboCop::RakeTask.new

task :ffi do
  Dir.chdir("lib/sequoia-ruby-ffi") do
    ruby "-S", "rake", "install"
  end
end

task default: %i[spec rubocop]
