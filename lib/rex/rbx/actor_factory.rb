# -*- coding: binary -*-

module Rbx

  ###
  #
  # This class provides a wrapper around Actor.new that can provide
  # additional features if a corresponding thread provider is set.
  #
  ###

  class ActorFactory

    @@provider = nil

    def self.provider=(val)
      @@provider = val
    end

    def self.spawn(name, crit, *args, &block)
      if @@provider
        if block
          return @@provider.spawn(name, crit, *args){ |*args_copy| block.call(*args_copy) }
        else
          return @@provider.spawn(name, crit, *args)
        end
      else
        t = nil
        if block
          t = Actor.new(*args){ |*args_copy| block.call(*args_copy) }
        else
          t = Actor.new(*args)
        end
        t[:tm_name] = name
        t[:tm_crit] = crit
        t[:tm_time] = Time.now
        t[:tm_call] = caller
        return t
      end

    end
  end

  #
  # Message class structs
  #
  ActorBlockCall = Struct.new(:args,:block)
  ActorPoolSpinUp = Struct.new(:size)
  ActorReady  = Struct.new(:this_actor)

  class ActorPool

    def initialize
      @supervisor = init_super
      @ready = Array.new
      @busy = Array.new
      @supervisor << ActorPoolSpinUp[12]
    end

    def init_super
      # Start external monitor thread
      supervision_loop = Actor.spawn do
        # Main supervisor loop
        loop do
          Actor.receive do |f|
            f.when(ActorPoolSpinUp) do |size|
              puts "Spinup #{size} actors"
              idx = 0
              size.times do
                puts idx
                @ready << Actor.spawn_link(work_loop.call)
                idx += 1
              end
            end

            f.when(ActorReady) do |this_actor|
              puts "Actor Ready"
              @ready << this_actor
            end

            f.when(ActorBlockCall) do |args, block|
              puts "Making block call"
              worker = @ready.pop
              worker << ActorBlockCall[args,block]
              @busy << worker
            end

            f.when(Rubinius::Actor::DeadActorError) do |exit|
              @ready << Actor.spawn_link(work_loop.call)
            end
          end
        end
      end
    end

    # Define operations for workers
    def work_loop
      return Proc.new do
        loop do
          work = Actor.receive
          if work.block
            work.block.call(*work.args)
          else
            args
          end
          @supervisor << ActorReady[Actor.current]
        end
      end
    end

    def get(*args,&block)
      begin
        worker = @ready.pop
        @supervisor << ActorPoolSpinUp[@ready.size + 1]
        if block
          worker << ActorBlockCall[args,block]
        end
        return worker
      rescue => e
        #Empty ready pool
        @supervisor << ActorPoolSpinUp[@ready.size + 1]
        retry
      end
    end

    def put(actor)
    end
  end

end
