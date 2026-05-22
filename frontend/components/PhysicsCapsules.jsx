import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const CAPSULE_THEMES = [
    { // Sunset Fire
        gradient: 'from-rose-500/20 to-orange-500/20',
        border: 'border-orange-500/35 hover:border-orange-450/70',
        text: 'text-orange-200 hover:text-white',
        glow: 'rgba(249, 115, 22, 0.22)',
        glowHover: 'rgba(249, 115, 22, 0.55)',
        dotColor: 'bg-orange-400',
    },
    { // Cyber Neon
        gradient: 'from-blue-600/20 to-cyan-500/20',
        border: 'border-cyan-500/35 hover:border-cyan-450/70',
        text: 'text-cyan-200 hover:text-white',
        glow: 'rgba(6, 182, 212, 0.22)',
        glowHover: 'rgba(6, 182, 212, 0.55)',
        dotColor: 'bg-cyan-400',
    },
    { // Cosmic Orchid
        gradient: 'from-violet-600/20 to-fuchsia-500/20',
        border: 'border-fuchsia-500/35 hover:border-fuchsia-450/70',
        text: 'text-fuchsia-200 hover:text-white',
        glow: 'rgba(217, 70, 239, 0.22)',
        glowHover: 'rgba(217, 70, 239, 0.55)',
        dotColor: 'bg-fuchsia-400',
    },
    { // Aurora Emerald
        gradient: 'from-teal-600/20 to-emerald-500/20',
        border: 'border-emerald-500/35 hover:border-emerald-450/70',
        text: 'text-emerald-200 hover:text-white',
        glow: 'rgba(16, 185, 129, 0.22)',
        glowHover: 'rgba(16, 185, 129, 0.55)',
        dotColor: 'bg-emerald-400',
    },
    { // Solar Gold
        gradient: 'from-amber-600/20 to-yellow-500/20',
        border: 'border-yellow-500/35 hover:border-yellow-450/70',
        text: 'text-yellow-100 hover:text-white',
        glow: 'rgba(234, 179, 8, 0.22)',
        glowHover: 'rgba(234, 179, 8, 0.55)',
        dotColor: 'bg-yellow-400',
    },
    { // Electric Indigo
        gradient: 'from-indigo-600/20 to-blue-500/20',
        border: 'border-blue-500/35 hover:border-blue-400/70',
        text: 'text-indigo-200 hover:text-white',
        glow: 'rgba(59, 130, 246, 0.22)',
        glowHover: 'rgba(59, 130, 246, 0.55)',
        dotColor: 'bg-indigo-400',
    },
    { // Rose Quartz
        gradient: 'from-pink-600/20 to-rose-500/20',
        border: 'border-rose-450/35 hover:border-rose-300/70',
        text: 'text-pink-200 hover:text-white',
        glow: 'rgba(244, 63, 94, 0.22)',
        glowHover: 'rgba(244, 63, 94, 0.55)',
        dotColor: 'bg-pink-400',
    },
    { // Neon Crimson
        gradient: 'from-red-600/20 to-rose-600/20',
        border: 'border-red-500/35 hover:border-red-400/70',
        text: 'text-red-200 hover:text-white',
        glow: 'rgba(239, 68, 68, 0.22)',
        glowHover: 'rgba(239, 68, 68, 0.55)',
        dotColor: 'bg-red-400',
    },
    { // Aqua Sea
        gradient: 'from-cyan-600/20 to-teal-500/20',
        border: 'border-teal-400/35 hover:border-teal-300/70',
        text: 'text-cyan-100 hover:text-white',
        glow: 'rgba(20, 184, 166, 0.22)',
        glowHover: 'rgba(20, 184, 166, 0.55)',
        dotColor: 'bg-teal-400',
    },
    { // Plum Dream
        gradient: 'from-purple-600/20 to-rose-500/20',
        border: 'border-purple-400/35 hover:border-purple-300/70',
        text: 'text-purple-200 hover:text-white',
        glow: 'rgba(168, 85, 247, 0.22)',
        glowHover: 'rgba(168, 85, 247, 0.55)',
        dotColor: 'bg-purple-400',
    }
];

const PhysicsCapsules = ({ capsules = [] }) => {
    const containerRef = useRef(null);
    const navigate = useNavigate();
    const [instances, setInstances] = useState([]);
    const [isMobile, setIsMobile] = useState(false);
    const [hoveredId, setHoveredId] = useState(-1);
    const instancesRef = useRef([]);
    const dragRef = useRef({
        index: -1,
        startX: 0,
        startY: 0,
        offsetX: 0,
        offsetY: 0,
        hasMoved: false,
        lastMouseX: 0,
        lastMouseY: 0,
        vx: 0,
        vy: 0,
    });

    useEffect(() => {
        const checkMobile = () => {
            setIsMobile(window.innerWidth < 768);
        };
        checkMobile();
        window.addEventListener('resize', checkMobile);
        return () => window.removeEventListener('resize', checkMobile);
    }, []);

    // Initialize physics bodies when capsules prop changes or mounts
    useEffect(() => {
        if (isMobile) return;
        if (!capsules || capsules.length === 0) return;

        const container = containerRef.current;
        if (!container) return;

        const rect = container.getBoundingClientRect();
        const width = rect.width || window.innerWidth;
        const height = rect.height || 500;

        const newInstances = capsules.map((cap, idx) => {
            // Calculate dynamic capsule width based on text length
            const textLen = cap.text ? cap.text.length : 15;
            const capWidth = Math.max(120, textLen * 7 + 48);
            const capHeight = 40;
            // Radius for circular collision approximation
            const radius = capWidth / 2.1;

            // Spawn capsules scattered horizontally, falling from the top
            const x = Math.min(width - radius, Math.max(radius, (width / (capsules.length + 1)) * (idx + 1) + (Math.random() - 0.5) * 40));
            const y = -40 - idx * 45; // Staggered entry from above top bounds

            return {
                ...cap,
                id: idx,
                x,
                y,
                vx: (Math.random() - 0.5) * 2, // Slight initial horizontal drift
                vy: Math.random() * 2 + 1,      // Falling velocity
                width: capWidth,
                height: capHeight,
                radius,
                mass: 1,
            };
        });

        instancesRef.current = newInstances;
        setInstances(newInstances);
    }, [capsules, isMobile]);

    // Core Animation and Physics Engine loop
    useEffect(() => {
        if (isMobile) return;
        let animationId;
        const gravity = 0.25;
        const bounce = 0.55;         // Restitution coefficient for walls
        const capsuleBounce = 0.65;  // Restitution coefficient between capsules
        const airResistance = 0.985;
        const groundFriction = 0.95;

        const updatePhysics = () => {
            const container = containerRef.current;
            if (!container) {
                animationId = requestAnimationFrame(updatePhysics);
                return;
            }

            const rect = container.getBoundingClientRect();
            const width = rect.width || window.innerWidth;
            const height = rect.height || 500;

            const list = [...instancesRef.current];
            const dragInfo = dragRef.current;

            // 1. Apply gravity & velocities
            list.forEach((body, idx) => {
                if (idx === dragInfo.index) {
                    // Body is being dragged, update position via dragInfo and calculate dragging velocity
                    const prevX = body.x;
                    const prevY = body.y;

                    body.x = dragInfo.lastMouseX - dragInfo.offsetX;
                    body.y = dragInfo.lastMouseY - dragInfo.offsetY;

                    // Bound-check dragging to keep inside container
                    body.x = Math.max(body.radius, Math.min(width - body.radius, body.x));
                    body.y = Math.max(body.radius, Math.min(height - body.radius, body.y));

                    body.vx = (body.x - prevX) * 0.8;
                    body.vy = (body.y - prevY) * 0.8;
                } else {
                    // Standard physics calculations
                    body.vy += gravity;
                    body.vx *= airResistance;
                    body.vy *= airResistance;

                    body.x += body.vx;
                    body.y += body.vy;
                }
            });

            // 2. Resolve elastic collisions between capsules (Circle-to-Circle Elastic Collision)
            for (let i = 0; i < list.length; i++) {
                for (let j = i + 1; j < list.length; j++) {
                    const b1 = list[i];
                    const b2 = list[j];

                    const dx = b2.x - b1.x;
                    const dy = b2.y - b1.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    const minDist = b1.radius + b2.radius;

                    if (distance < minDist && distance > 0) {
                        // Resolve overlap immediately (static resolution)
                        const overlap = minDist - distance;
                        const nx = dx / distance;
                        const ny = dy / distance;

                        // Separate them relative to drag state (if one is dragged, only push the other)
                        if (i === dragInfo.index) {
                            b2.x += nx * overlap;
                            b2.y += ny * overlap;
                        } else if (j === dragInfo.index) {
                            b1.x -= nx * overlap;
                            b1.y -= ny * overlap;
                        } else {
                            b1.x -= nx * overlap * 0.5;
                            b1.y -= ny * overlap * 0.5;
                            b2.x += nx * overlap * 0.5;
                            b2.y += ny * overlap * 0.5;
                        }

                        // Relative velocity along normal
                        const rvx = b2.vx - b1.vx;
                        const rvy = b2.vy - b1.vy;
                        const velAlongNormal = rvx * nx + rvy * ny;

                        // Only bounce if they are moving towards each other
                        if (velAlongNormal < 0) {
                            const impulse = -(1 + capsuleBounce) * velAlongNormal;
                            const impulseX = impulse * nx * 0.5;
                            const impulseY = impulse * ny * 0.5;

                            if (i !== dragInfo.index) {
                                b1.vx -= impulseX;
                                b1.vy -= impulseY;
                            }
                            if (j !== dragInfo.index) {
                                b2.vx += impulseX;
                                b2.vy += impulseY;
                            }
                        }
                    }
                }
            }

            // 3. Resolve boundary collisions
            list.forEach((body, idx) => {
                // Bottom wall boundary
                if (body.y + body.radius > height) {
                    body.y = height - body.radius;
                    body.vy = -body.vy * bounce;
                    body.vx *= groundFriction; // Rolling friction on bottom wall
                }
                // Top wall boundary (stoppers)
                else if (body.y - body.radius < 0) {
                    body.y = body.radius;
                    body.vy = -body.vy * bounce;
                }

                // Left wall boundary
                if (body.x - body.radius < 0) {
                    body.x = body.radius;
                    body.vx = -body.vx * bounce;
                }
                // Right wall boundary
                else if (body.x + body.radius > width) {
                    body.x = width - body.radius;
                    body.vx = -body.vx * bounce;
                }
            });

            instancesRef.current = list;
            setInstances(list);

            animationId = requestAnimationFrame(updatePhysics);
        };

        animationId = requestAnimationFrame(updatePhysics);
        return () => cancelAnimationFrame(animationId);
    }, [isMobile]);

    // Mouse handlers
    const handleMouseDown = (e, index) => {
        e.preventDefault();
        const container = containerRef.current;
        if (!container) return;

        const rect = container.getBoundingClientRect();
        // Mouse coordinate relative to the container
        const clientX = e.touches ? e.touches[0].clientX : e.clientX;
        const clientY = e.touches ? e.touches[0].clientY : e.clientY;
        const mouseX = clientX - rect.left;
        const mouseY = clientY - rect.top;

        const body = instancesRef.current[index];
        if (!body) return;

        dragRef.current = {
            index,
            startX: mouseX,
            startY: mouseY,
            offsetX: mouseX - body.x,
            offsetY: mouseY - body.y,
            hasMoved: false,
            lastMouseX: mouseX,
            lastMouseY: mouseY,
            vx: 0,
            vy: 0,
        };

        // Attach global mouse listeners to capture drag movement outside capsule boundary
        if (!e.touches) {
            window.addEventListener('mousemove', handleMouseMoveGlobal);
            window.addEventListener('mouseup', handleMouseUpGlobal);
        }
    };

    const handleMouseMoveGlobal = (e) => {
        const container = containerRef.current;
        const dragInfo = dragRef.current;
        if (!container || dragInfo.index === -1) return;

        const rect = container.getBoundingClientRect();
        const clientX = e.touches ? e.touches[0].clientX : e.clientX;
        const clientY = e.touches ? e.touches[0].clientY : e.clientY;
        const mouseX = clientX - rect.left;
        const mouseY = clientY - rect.top;

        // Check if movement is significant to distinguish drag vs simple click click
        const moveDist = Math.sqrt(Math.pow(mouseX - dragInfo.startX, 2) + Math.pow(mouseY - dragInfo.startY, 2));
        if (moveDist > 5) {
            dragInfo.hasMoved = true;
        }

        dragInfo.lastMouseX = mouseX;
        dragInfo.lastMouseY = mouseY;
    };

    const handleMouseUpGlobal = () => {
        const dragInfo = dragRef.current;
        if (dragInfo.index === -1) return;

        const clickedBody = instancesRef.current[dragInfo.index];

        // Global event cleanup
        window.removeEventListener('mousemove', handleMouseMoveGlobal);
        window.removeEventListener('mouseup', handleMouseUpGlobal);

        const index = dragInfo.index;
        dragRef.current.index = -1; // Reset drag state

        // If it was just a click (little to no mouse travel), navigate to the link!
        if (!dragInfo.hasMoved && clickedBody) {
            const link = clickedBody.link;
            if (link) {
                if (link.startsWith('http') || link.startsWith('//')) {
                    window.open(link, '_blank');
                } else {
                    navigate(link);
                }
            }
        }
    };

    // Mobile touch handlers
    const handleTouchStart = (e, index) => {
        handleMouseDown(e, index);
    };

    const handleTouchMove = (e) => {
        handleMouseMoveGlobal(e);
    };

    const handleTouchEnd = () => {
        handleMouseUpGlobal();
    };

    if (isMobile) return null;

    return (
        <div
            ref={containerRef}
            className="absolute inset-0 w-full h-full overflow-hidden select-none z-10 pointer-events-none"
            onTouchMove={handleTouchMove}
            onTouchEnd={handleTouchEnd}
        >
            {instances.map((body) => {
                const theme = CAPSULE_THEMES[body.id % CAPSULE_THEMES.length];
                const isHovered = hoveredId === body.id;
                const isDragged = dragRef.current.index === body.id;
                const shadowGlow = isHovered || isDragged ? theme.glowHover : theme.glow;
                const scale = isHovered || isDragged ? 'scale(1.06)' : 'scale(1)';

                return (
                    <div
                        key={body.id}
                        onMouseDown={(e) => handleMouseDown(e, body.id)}
                        onTouchStart={(e) => handleTouchStart(e, body.id)}
                        onMouseEnter={() => setHoveredId(body.id)}
                        onMouseLeave={() => setHoveredId(-1)}
                        style={{
                            position: 'absolute',
                            width: `${body.width}px`,
                            height: `${body.height}px`,
                            left: 0,
                            top: 0,
                            transform: `translate3d(${body.x - body.width / 2}px, ${body.y - body.height / 2}px, 0) ${scale}`,
                            willChange: 'transform',
                            boxShadow: `0 8px 32px 0 rgba(0,0,0,0.35), 0 0 15px ${shadowGlow}`,
                            transition: 'border-color 0.2s, background-color 0.2s, color 0.2s, box-shadow 0.2s, transform 0.05s ease-out',
                        }}
                        className={`
                            pointer-events-auto cursor-grab active:cursor-grabbing select-none
                            flex items-center justify-center rounded-full px-5 py-2.5 text-xs font-black
                            border backdrop-blur-lg
                            bg-gradient-to-r ${theme.gradient} ${theme.border} ${theme.text}
                        `}
                    >
                        <span className={`w-2.5 h-2.5 rounded-full ${theme.dotColor} mr-2.5 shadow-[0_0_8px_currentColor] animate-pulse`} />
                        <span className="truncate max-w-[85%] text-center font-extrabold tracking-wide drop-shadow-[0_1px_2px_rgba(0,0,0,0.4)]">
                            {body.text}
                        </span>
                    </div>
                );
            })}
        </div>
    );
};

export default PhysicsCapsules;
